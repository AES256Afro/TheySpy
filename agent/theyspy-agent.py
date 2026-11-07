#!/usr/bin/env python3
"""TheySpy agent: runs zero-breach's scanner on this computer and reports to your TheySpy.

    python3 theyspy-agent.py enroll https://theyspy.example:8797 tse_ONE_TIME_TOKEN
    python3 theyspy-agent.py run            # scan and report
    python3 theyspy-agent.py run --quick    # skip file fingerprinting (reported as a gap)
    python3 theyspy-agent.py install        # schedule "run" daily (cron, launchd or Task Scheduler)
    python3 theyspy-agent.py install --every 12h [--quick] [--print]
    python3 theyspy-agent.py uninstall      # remove that schedule
    ... --insecure                          # allow a http:// TheySpy (readable on the network)

What it does, and does not do:
  * It downloads zero-breach's scanner from your TheySpy and checks its SHA-256 against the hash
    pinned in this file - zero-breach's own released hash, not one the server supplies - then runs
    it unmodified. So a TheySpy that has been tampered with cannot hand this computer a different
    program to run. The scanner only reads; it never contacts an indicator and refuses to run if
    anything tries.
  * It needs an https:// address, because enrolment hands this computer its signing key.
  * It reads the versions of this computer's OS and browsers, for matching CVEs.
  * It sends one report to your TheySpy, signed with this computer's own key. Nothing else leaves.
Standard library only; Python 3.9 or later; Windows, macOS and Linux.
"""
import hashlib
import hmac
import json
import os
import platform
import plistlib
import re
import shutil
import ssl
import subprocess
import sys
import tempfile
import urllib.request
import uuid
from datetime import datetime, timezone

VERSION = "1.1"

# zero-breach's released scanner, as its signed SHA256SUMS.txt gives it. TheySpy checks the
# signature; this is checked here as well so the agent does not have to take the server's word for
# what it is about to execute. When TheySpy vendors a newer zero-breach, update the agent too
# (your TheySpy serves the current one at /agent/theyspy-agent.py).
SCANNER_VERSION = "0.1.8"
SCANNER_SHA256 = "74740af20f609f82dc6e50d66f234d0c39a20f516caa35731c2d19c11684ef44"


def check_server(url, insecure=False):
    """Refuses a server that cannot keep the enrolment token and this computer's key private."""
    if url.startswith("https://"):
        return
    if not insecure:
        raise SystemExit(
            "Refusing to use {}.\n"
            "Without HTTPS the enrolment token, this computer's signing key and every report are\n"
            "readable by anything on the network - the network TheySpy exists to distrust.\n"
            "Use an https:// address, or pass --insecure if this link is private by other means\n"
            "(a Tailscale or WireGuard address, or localhost).".format(url)
        )
    print("Warning: {} is not HTTPS. The token, this computer's key and every report are readable on the network.".format(url), file=sys.stderr)


def config_path():
    base = os.environ.get("APPDATA") if os.name == "nt" else os.path.join(os.path.expanduser("~"), ".config")
    return os.path.join(base or os.path.expanduser("~"), "theyspy-agent.json")


def load_config():
    with open(config_path(), "r", encoding="utf-8") as f:
        return json.load(f)


def save_config(cfg):
    path = config_path()
    os.makedirs(os.path.dirname(path), exist_ok=True)
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    with os.fdopen(fd, "w", encoding="utf-8") as f:
        json.dump(cfg, f, indent=2)


def request(url, data=None, headers=None, timeout=120):
    req = urllib.request.Request(url, data=data, headers={"User-Agent": "theyspy-agent/" + VERSION, "X-TheySpy": "1", **(headers or {})})
    ctx = ssl.create_default_context()
    if os.environ.get("THEYSPY_CA_FILE"):
        ctx.load_verify_locations(os.environ["THEYSPY_CA_FILE"])
    with urllib.request.urlopen(req, timeout=timeout, context=ctx if url.startswith("https:") else None) as r:
        return r.read()


def macs():
    out = set()
    node = uuid.getnode()
    if not (node >> 40) & 1:  # a real, globally administered address
        out.add(":".join("{:02x}".format((node >> s) & 0xFF) for s in range(40, -1, -8)))
    try:
        if os.path.isdir("/sys/class/net"):
            for name in os.listdir("/sys/class/net"):
                with open("/sys/class/net/{}/address".format(name)) as f:
                    a = f.read().strip()
                if a and a != "00:00:00:00:00:00":
                    out.add(a)
    except OSError:
        pass
    return sorted(out)[:16]


def run_quiet(args):
    try:
        return subprocess.run(args, capture_output=True, text=True, timeout=20).stdout.strip()
    except (OSError, subprocess.SubprocessError):
        return ""


def plist_version(app):
    try:
        with open(os.path.join(app, "Contents", "Info.plist"), "rb") as f:
            return plistlib.load(f).get("CFBundleShortVersionString")
    except (OSError, ValueError):
        return None


def inventory():
    """The OS and browser versions this computer runs: (software, version) pairs TheySpy knows."""
    items = []
    system = platform.system()
    if system == "Darwin":
        items.append({"software": "macos", "version": platform.mac_ver()[0]})
        for software, app in (("chrome", "Google Chrome"), ("firefox", "Firefox"), ("edge", "Microsoft Edge"), ("brave", "Brave Browser"), ("safari", "Safari")):
            v = plist_version("/Applications/{}.app".format(app))
            if v:
                items.append({"software": software, "version": v})
    elif system == "Windows":
        items.append({"software": "windows", "version": platform.version()})
        try:
            import winreg
            for software, key in (("chrome", r"SOFTWARE\Google\Chrome\BLBeacon"), ("edge", r"SOFTWARE\Microsoft\Edge\BLBeacon")):
                try:
                    with winreg.OpenKey(winreg.HKEY_CURRENT_USER, key) as k:
                        items.append({"software": software, "version": winreg.QueryValueEx(k, "version")[0]})
                except OSError:
                    pass
            try:
                with winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, r"SOFTWARE\Mozilla\Mozilla Firefox") as k:
                    items.append({"software": "firefox", "version": winreg.QueryValueEx(k, "CurrentVersion")[0].split(" ")[0]})
            except OSError:
                pass
        except ImportError:
            pass
    else:
        for software, cmd in (("chrome", ["google-chrome", "--version"]), ("chrome", ["chromium", "--version"]), ("firefox", ["firefox", "--version"])):
            m = re.search(r"(\d+(?:\.\d+)+)", run_quiet(cmd))
            if m and not any(i["software"] == software for i in items):
                items.append({"software": software, "version": m.group(1)})
    m = re.search(r"OpenSSH_([\w.]+)", run_quiet(["ssh", "-V"]) or "")
    if not m:
        try:
            m = re.search(r"OpenSSH_([\w.]+)", subprocess.run(["ssh", "-V"], capture_output=True, text=True, timeout=10).stderr)
        except (OSError, subprocess.SubprocessError):
            m = None
    if m:
        items.append({"software": "openssh", "version": m.group(1)})
    return [i for i in items if i.get("version")]


def signed(cfg, payload):
    """The headers TheySpy checks: HMAC-SHA256 of "<timestamp>.<payload>" under this computer's key."""
    stamp = datetime.now(timezone.utc).isoformat()
    body = payload if isinstance(payload, bytes) else payload.encode()
    return stamp, {
        "X-TheySpy-Agent": str(cfg["agentId"]),
        "X-TheySpy-Timestamp": stamp,
        "X-TheySpy-Signature": hmac.new(cfg["secret"].encode(), stamp.encode() + b"." + body, hashlib.sha256).hexdigest(),
    }


def get_signed(cfg, path):
    """A read TheySpy only answers for an enrolled agent: the indicator set is the owner's own."""
    _, headers = signed(cfg, "GET " + path)
    return request(cfg["server"] + path, None, headers)


def enroll(server, token, insecure=False):
    server = server.rstrip("/")
    check_server(server, insecure)
    body = json.dumps({"token": token, "hostname": platform.node(), "platform": platform.system(), "macs": macs()}).encode()
    answer = json.loads(request(server + "/api/agent/enroll", body, {"Content-Type": "application/json"}))
    save_config({"server": server, "agentId": answer["agentId"], "secret": answer["secret"]})
    print("Enrolled as agent {} with {}. Saved to {}.".format(answer["agentId"], server, config_path()))
    print("Now run:  {} {} run   (and schedule it daily)".format(sys.executable, os.path.abspath(__file__)))


def scan(cfg, quick):
    """Downloads the scanner and indicators, checks them, runs the scan; returns (exit code, report or None, error).

    Everything is inside the try: a failure here has to come back as a gap on the dashboard, not as
    a traceback and a device still showing last week's verdict.
    """
    work = None
    try:
        meta = json.loads(get_signed(cfg, "/api/agent/scanner"))
        work = tempfile.mkdtemp(prefix="theyspy-agent-")
        scanner = get_signed(cfg, "/api/agent/zero-breach.py")
        # Against the hash in this file, not the one the server just sent with it.
        if meta.get("version") != SCANNER_VERSION:
            return 1, None, "TheySpy offers zero-breach {} but this agent only trusts {}; update the agent from {}/agent/theyspy-agent.py".format(
                meta.get("version"), SCANNER_VERSION, cfg["server"])
        if hashlib.sha256(scanner).hexdigest() != SCANNER_SHA256:
            return 1, None, "the scanner TheySpy sent is not zero-breach {} (its hash does not match the one pinned in this agent); not running it".format(SCANNER_VERSION)
        # The indicator file is the owner's own live set, so there is no hash to pin: it is data the
        # scanner reads, not code it runs. TheySpy's own hash for it is still checked.
        iocs = get_signed(cfg, "/api/agent/iocs.txt")
        if hashlib.sha256(iocs).hexdigest() != meta["iocsSha256"]:
            return 1, None, "the indicator file does not match TheySpy's hash; not running"
        sp, ip, rp = (os.path.join(work, n) for n in ("zero-breach.py", "iocs.txt", "report.json"))
        for path, data in ((sp, scanner), (ip, iocs)):
            with open(path, "wb") as f:
                f.write(data)
        args = [sys.executable, sp, "--no-pause", "--iocs", ip, "--json", rp] + (["--quick"] if quick else [])
        done = subprocess.run(args, capture_output=True, text=True, timeout=3600)
        if os.path.exists(rp):
            with open(rp, "r", encoding="utf-8") as f:
                return done.returncode, json.load(f), None
        return done.returncode, None, (done.stderr or done.stdout)[-500:] or "the scanner wrote no report"
    except Exception as error:  # report the failure as a gap rather than nothing
        return 1, None, str(error)[:500]
    finally:
        if work:
            # rmtree, not a remove per entry: a directory the scanner left would raise in here and
            # hide whatever actually went wrong.
            shutil.rmtree(work, ignore_errors=True)


def run(quick=False, insecure=False):
    cfg = load_config()
    check_server(cfg["server"], insecure)
    code, report, error = scan(cfg, quick)
    body = json.dumps({
        "agentVersion": VERSION, "hostname": platform.node(), "platform": platform.system(), "macs": macs(),
        "inventory": inventory(), "scan": {"exitCode": code, "report": report, "error": error},
        "schedule": {"everyHours": cfg.get("everyHours")} if cfg.get("everyHours") else None,
    }).encode()
    _, headers = signed(cfg, body)
    try:
        answer = json.loads(request(cfg["server"] + "/api/agent/report", body, {"Content-Type": "application/json", **headers}))
    except Exception as failure:
        print("Could not report to {}: {}".format(cfg["server"], failure), file=sys.stderr)
        print("The scan itself {}. Nothing was recorded; run it again.".format("found something" if report else "did not complete"), file=sys.stderr)
        return 1
    v = answer.get("verdict", {})
    print("Reported: {} · {} indicator hit(s) · {} gap(s).".format(v.get("status"), v.get("hits"), answer.get("gaps")))
    return 2 if v.get("hits") else (1 if report is None else 0)


# --- the schedule (docs/PLAN.md M41) -----------------------------------------------------------

SCHEDULE_LABEL = "com.theyspy.agent"


def parse_every(argv):
    """--every 12h / --every 2d (1 hour to 7 days); daily when absent."""
    if "--every" not in argv:
        return 24
    value = argv[argv.index("--every") + 1] if argv.index("--every") + 1 < len(argv) else ""
    m = re.fullmatch(r"(\d+)\s*([hd]?)", value.strip().lower())
    if not m:
        raise SystemExit("--every takes hours or days, such as 12h or 2d")
    hours = int(m.group(1)) * (24 if m.group(2) == "d" else 1)
    if not 1 <= hours <= 168:
        raise SystemExit("--every must be between 1h and 7d")
    return hours


def schedule_plan(system, script, python, every_hours, quick=False):
    """What installing the schedule writes or runs on a platform, as data, so it can be shown or tested."""
    args = [python, script, "run"] + (["--quick"] if quick else [])
    command = " ".join('"{}"'.format(a) if " " in a else a for a in args)
    if system == "Darwin":
        plist = os.path.join(os.path.expanduser("~"), "Library", "LaunchAgents", SCHEDULE_LABEL + ".plist")
        body = plistlib.dumps({"Label": SCHEDULE_LABEL, "ProgramArguments": args, "StartInterval": every_hours * 3600, "RunAtLoad": False,
                               "StandardOutPath": os.path.join(os.path.expanduser("~"), "Library", "Logs", "theyspy-agent.log"),
                               "StandardErrorPath": os.path.join(os.path.expanduser("~"), "Library", "Logs", "theyspy-agent.log")}, sort_keys=False).decode()
        return {"kind": "launchd", "path": plist, "content": body, "load": ["launchctl", "load", "-w", plist], "unload": ["launchctl", "unload", "-w", plist]}
    if system == "Windows":
        task = "TheySpyAgent"
        when = ["/SC", "DAILY", "/ST", "09:00"] if every_hours >= 24 else ["/SC", "HOURLY", "/MO", str(every_hours)]
        if every_hours > 24:
            when = ["/SC", "DAILY", "/MO", str(every_hours // 24), "/ST", "09:00"]
        return {"kind": "schtasks", "task": task, "create": ["schtasks", "/Create", "/F", "/TN", task, "/TR", command] + when, "delete": ["schtasks", "/Delete", "/F", "/TN", task]}
    # Linux and the rest: the user's crontab, one marked line.
    if every_hours >= 24:
        field = "0 9 */{} * *".format(every_hours // 24) if every_hours > 24 else "0 9 * * *"
    else:
        field = "0 */{} * * *".format(every_hours)
    line = "{} {} # {}".format(field, command, SCHEDULE_LABEL)
    return {"kind": "cron", "line": line, "marker": SCHEDULE_LABEL}


def install_schedule(argv):
    every = parse_every(argv)
    quick = "--quick" in argv
    cfg = load_config()  # enrol first: the schedule is pointless without a key
    plan = schedule_plan(platform.system(), os.path.abspath(__file__), sys.executable or "python3", every, quick)
    if "--print" in argv:
        print(json.dumps(plan, indent=2))
        return 0
    if plan["kind"] == "launchd":
        os.makedirs(os.path.dirname(plan["path"]), exist_ok=True)
        subprocess.run(plan["unload"], capture_output=True)
        with open(plan["path"], "w", encoding="utf-8") as f:
            f.write(plan["content"])
        subprocess.run(plan["load"], check=True)
    elif plan["kind"] == "schtasks":
        subprocess.run(plan["create"], check=True)
    else:
        current = subprocess.run(["crontab", "-l"], capture_output=True, text=True)
        lines = [l for l in (current.stdout.splitlines() if current.returncode == 0 else []) if plan["marker"] not in l]
        lines.append(plan["line"])
        subprocess.run(["crontab", "-"], input="\n".join(lines) + "\n", text=True, check=True)
    cfg["everyHours"] = every
    save_config(cfg)
    print("Scheduled: every {} hour(s) via {}. TheySpy will count a report overdue after twice that.".format(every, plan["kind"]))
    return 0


def uninstall_schedule():
    plan = schedule_plan(platform.system(), os.path.abspath(__file__), sys.executable or "python3", 24)
    if plan["kind"] == "launchd":
        subprocess.run(plan["unload"], capture_output=True)
        if os.path.exists(plan["path"]):
            os.remove(plan["path"])
    elif plan["kind"] == "schtasks":
        subprocess.run(plan["delete"], capture_output=True)
    else:
        current = subprocess.run(["crontab", "-l"], capture_output=True, text=True)
        if current.returncode == 0:
            lines = [l for l in current.stdout.splitlines() if plan["marker"] not in l]
            subprocess.run(["crontab", "-"], input="\n".join(lines) + ("\n" if lines else ""), text=True, check=True)
    try:
        cfg = load_config()
        cfg.pop("everyHours", None)
        save_config(cfg)
    except FileNotFoundError:
        pass
    print("Schedule removed.")
    return 0


def main(argv):
    insecure = "--insecure" in argv
    if len(argv) >= 3 and argv[0] == "enroll":
        enroll(argv[1], argv[2], insecure)
        return 0
    if argv and argv[0] == "run":
        return run(quick="--quick" in argv, insecure=insecure)
    if argv and argv[0] == "install":
        return install_schedule(argv[1:])
    if argv and argv[0] == "uninstall":
        return uninstall_schedule()
    print(__doc__)
    return 64


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
