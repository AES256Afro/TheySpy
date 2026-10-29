import { domainToASCII } from "node:url";

// Reads DNS blocklists in the formats people publish them in, into one set of hostnames:
//   hosts          0.0.0.0 ads.example     (also 127.0.0.1, ::, ::1, 0)
//   domains        ads.example             (also "*.ads.example")
//   Adblock        ||ads.example^          (plain domain rules only; anything with a path,
//                                           options other than $important, or an exception is skipped)
//   dnsmasq        address=/ads.example/0.0.0.0   or   server=/ads.example/
//   RPZ            ads.example CNAME .     (and *.ads.example CNAME .)
// Every name is lower-cased, has its trailing dot removed, is converted to punycode and must be a
// valid hostname. IP addresses, localhost names and blank or comment lines are dropped.

const ignoreNames = new Set(["localhost", "localhost.localdomain", "local", "broadcasthost", "ip6-localhost", "ip6-loopback", "ip6-localnet", "ip6-mcastprefix", "ip6-allnodes", "ip6-allrouters", "ip6-allhosts", "0.0.0.0"]);
const sinkholes = new Set(["0.0.0.0", "127.0.0.1", "::", "::1", "0", "255.255.255.255", "fe80::1%lo0", "ff00::0", "ff02::1", "ff02::2", "ff02::3"]);
const labelPattern = /^[a-z0-9_]([a-z0-9_-]{0,61}[a-z0-9_])?$/;

/** A valid hostname in canonical form, or null. */
export function canonical(raw) {
  let name = String(raw ?? "").trim().toLowerCase().replace(/\.+$/, "").replace(/^\*\./, "");
  if (!name || name.length > 253 || ignoreNames.has(name)) return null;
  if (/^[\d.]+$/.test(name) || name.includes(":")) return null; // an IP address, not a name
  if (!/^\p{ASCII}*$/u.test(name)) {
    name = domainToASCII(name);
    if (!name) return null;
  }
  const labels = name.split(".");
  if (labels.length < 2 || !labels.every((l) => labelPattern.test(l))) return null;
  return name;
}

function lineDomain(line) {
  // Adblock: ||name^ with nothing after, or only $important
  if (line.startsWith("||")) {
    const m = /^\|\|([^/^$|*]+)\^(\$important)?$/.exec(line);
    return m ? m[1] : null;
  }
  if (line.startsWith("@@") || line.startsWith("|") || line.startsWith("/") || line.includes("##") || line.includes("#@#")) return null;
  // dnsmasq
  let m = /^(?:address|server|local)=\/([^/]+)\//.exec(line);
  if (m) return m[1];
  // RPZ: name CNAME .
  m = /^(\S+)\s+(?:\d+\s+)?(?:IN\s+)?CNAME\s+\.(?:\s|$)/i.exec(line);
  if (m) return m[1];
  const parts = line.split(/\s+/);
  // hosts: <sink address> name [more names]
  if (parts.length >= 2 && sinkholes.has(parts[0])) return parts.slice(1);
  if (parts.length === 1) return parts[0];
  return null;
}

/**
 * @param {string} text the downloaded list
 * @returns {{ domains: Set<string>, lines: number, skipped: number }}
 */
export function parseBlocklist(text) {
  const domains = new Set();
  let lines = 0;
  let skipped = 0;
  for (let raw of text.replace(/^\uFEFF/, "").split(/\r?\n/)) {
    raw = raw.replace(/\s#.*$/, "").trim(); // trailing comments in hosts files
    if (!raw || raw.startsWith("#") || raw.startsWith("!") || raw.startsWith("[") || raw.startsWith(";") || raw.startsWith("$")) continue;
    lines += 1;
    const found = lineDomain(raw);
    const names = Array.isArray(found) ? found : found ? [found] : [];
    let any = false;
    for (const n of names) {
      const name = canonical(n);
      if (name) { domains.add(name); any = true; }
    }
    if (!any) skipped += 1;
  }
  return { domains, lines, skipped };
}

// Names a blocklist must never take away: connectivity and captive-portal checks, certificate
// revocation, time, OS and package updates, and the services TheySpy and BoxPilot themselves need.
// An update that newly adds one of these is held for review; compiled lists always leave them out.
export const neverBlock = Object.freeze([
  "connectivitycheck.gstatic.com", "connectivitycheck.android.com", "clients3.google.com", "captive.apple.com", "www.apple.com",
  "www.msftconnecttest.com", "www.msftncsi.com", "detectportal.firefox.com", "connectivity-check.ubuntu.com", "nmcheck.gnome.org", "network-test.debian.org",
  "ocsp.digicert.com", "ocsp.pki.goog", "ocsp.sectigo.com", "ocsp.usertrust.com", "ocsp.apple.com", "ocsp2.apple.com", "ocsp.globalsign.com", "ocsp.entrust.net",
  "crl3.digicert.com", "crl4.digicert.com", "r3.o.lencr.org", "r10.o.lencr.org", "r11.o.lencr.org", "e5.o.lencr.org", "e6.o.lencr.org", "x1.c.lencr.org",
  "acme-v02.api.letsencrypt.org", "time.apple.com", "time.windows.com", "time.google.com", "time.cloudflare.com", "pool.ntp.org", "ntp.ubuntu.com", "time.nist.gov",
  "archive.ubuntu.com", "security.ubuntu.com", "ports.ubuntu.com", "deb.debian.org", "security.debian.org", "dl-cdn.alpinelinux.org",
  "registry-1.docker.io", "auth.docker.io", "production.cloudflare.docker.com", "ghcr.io", "pkg-containers.githubusercontent.com",
  "github.com", "api.github.com", "raw.githubusercontent.com", "objects.githubusercontent.com", "codeload.github.com",
  "registry.npmjs.org", "nodejs.org", "pypi.org", "files.pythonhosted.org",
  "controlplane.tailscale.com", "login.tailscale.com", "derp1.tailscale.com", "pi-hole.net", "ftl.pi-hole.net",
  "mesu.apple.com", "swscan.apple.com", "swdist.apple.com", "updates.cdn-apple.com", "windowsupdate.microsoft.com", "update.microsoft.com", "dl.google.com",
]);
