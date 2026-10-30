#!/usr/bin/env python3
"""TheySpy agent: runs zero-breach's scanner on this computer and reports to your TheySpy.

    python3 theyspy-agent.py enroll https://theyspy.example:8797 tse_ONE_TIME_TOKEN
    python3 theyspy-agent.py run            # scan and report (schedule this daily)
    python3 theyspy-agent.py run --quick    # skip file fingerprinting (reported as a gap)

What it does, and does not do:
  * It downloads zero-breach's scanner from your TheySpy, checks its SHA-256 against the hash
    TheySpy verified from zero-breach's signed release, and runs it unmodified. The scanner only
    reads; it never contacts an indicator and refuses to run if anything tries.
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
import ssl
import subprocess
import sys
import tempfile
import urllib.request
import uuid
from datetime import datetime, timezone

VERSION = "1.0"


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


def enroll(server, token):
    server = server.rstrip("/")
    body = json.dumps({"token": token, "hostname": platform.node(), "platform": platform.system(), "macs": macs()}).encode()
    answer = json.loads(request(server + "/api/agent/enroll", body, {"Content-Type": "application/json"}))
    save_config({"server": server, "agentId": answer["agentId"], "secret": answer["secret"]})
    print("Enrolled as agent {} with {}. Saved to {}.".format(answer["agentId"], server, config_path()))
    print("Now run:  {} {} run   (and schedule it daily)".format(sys.executable, os.path.abspath(__file__)))


def scan(cfg, quick):
    """Downloads the scanner and indicators, checks them, runs the scan; returns (exit code, report or None, error)."""
    meta = json.loads(request(cfg["server"] + "/api/agent/scanner"))
    work = tempfile.mkdtemp(prefix="theyspy-agent-")
    try:
        scanner = request(cfg["server"] + "/api/agent/zero-breach.py")
        if hashlib.sha256(scanner).hexdigest() != meta["sha256"]:
            return 1, None, "the scanner TheySpy sent does not match the signed hash; not running it"
        iocs = request(cfg["server"] + "/api/agent/iocs.txt")
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
        for name in os.listdir(work):
            os.remove(os.path.join(work, name))
        os.rmdir(work)


def run(quick=False):
    cfg = load_config()
    code, report, error = scan(cfg, quick)
    body = json.dumps({
        "agentVersion": VERSION, "hostname": platform.node(), "platform": platform.system(), "macs": macs(),
        "inventory": inventory(), "scan": {"exitCode": code, "report": report, "error": error},
    }).encode()
    stamp = datetime.now(timezone.utc).isoformat()
    signature = hmac.new(cfg["secret"].encode(), stamp.encode() + b"." + body, hashlib.sha256).hexdigest()
    answer = json.loads(request(cfg["server"] + "/api/agent/report", body, {
        "Content-Type": "application/json", "X-TheySpy-Agent": str(cfg["agentId"]), "X-TheySpy-Timestamp": stamp, "X-TheySpy-Signature": signature,
    }))
    v = answer.get("verdict", {})
    print("Reported: {} · {} indicator hit(s) · {} gap(s).".format(v.get("status"), v.get("hits"), answer.get("gaps")))
    return 2 if v.get("hits") else (1 if report is None else 0)


def main(argv):
    if len(argv) >= 3 and argv[0] == "enroll":
        enroll(argv[1], argv[2])
        return 0
    if argv and argv[0] == "run":
        return run(quick="--quick" in argv)
    print(__doc__)
    return 64


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
