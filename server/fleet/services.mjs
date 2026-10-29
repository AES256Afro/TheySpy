import net from "node:net";
import tls from "node:tls";

// Port checks for the targeted check (docs/PLAN.md M4): plain TCP connections, no privileges and no
// nmap. For each open port a banner is read (or an HTTP HEAD sent) to name the product and version,
// which M6 matches against CVEs. Ports that are risky to leave open on a home network say why.

/** Ports worth checking on a home network, with what usually listens there. */
export const commonPorts = Object.freeze({
  21: "ftp", 22: "ssh", 23: "telnet", 25: "smtp", 53: "dns", 80: "http", 81: "http", 88: "kerberos", 110: "pop3", 111: "rpcbind", 135: "msrpc", 139: "netbios",
  143: "imap", 389: "ldap", 443: "https", 445: "smb", 515: "lpd", 548: "afp", 554: "rtsp", 587: "submission", 631: "ipp", 873: "rsync", 993: "imaps", 995: "pop3s",
  1080: "socks", 1400: "sonos", 1883: "mqtt", 2049: "nfs", 2375: "docker", 2376: "docker-tls", 3000: "http", 3128: "http-proxy", 3306: "mysql", 3389: "rdp",
  3689: "daap", 4443: "https", 5000: "http", 5001: "https", 5060: "sip", 5432: "postgresql", 5555: "adb", 5900: "vnc", 6379: "redis", 6443: "kubernetes",
  7000: "airplay", 7547: "tr-069", 8000: "http", 8008: "http", 8009: "cast", 8080: "http", 8081: "http", 8123: "home-assistant", 8443: "https", 8554: "rtsp",
  8883: "mqtts", 8888: "http", 9000: "http", 9090: "http", 9100: "jetdirect", 9200: "elasticsearch", 9443: "https", 10000: "http", 11211: "memcached",
  27017: "mongodb", 32400: "plex", 49152: "upnp", 62078: "iphone-sync",
});

/** Open ports that deserve a look, and why. */
export const riskyPorts = Object.freeze({
  21: "FTP sends passwords in the clear.",
  23: "Telnet: remote login with no encryption; a favourite of IoT botnets.",
  135: "Windows RPC reachable from the network.",
  445: "Windows file sharing (SMB) reachable from the network.",
  1080: "An open SOCKS proxy can relay anyone's traffic.",
  2375: "Docker's API without TLS: full control of the host.",
  3389: "Remote Desktop: a common way in; keep it off the LAN unless needed.",
  5555: "Android Debug Bridge: full control of the device from the network.",
  5900: "VNC: remote screen control, often with a weak or no password.",
  6379: "Redis, often with no password.",
  7547: "TR-069 router management, a frequent target.",
  9200: "Elasticsearch, often with no authentication.",
  11211: "Memcached, no authentication.",
  27017: "MongoDB, often with no authentication.",
});

const tlsPorts = new Set([443, 993, 995, 2376, 4443, 5001, 6443, 8443, 8883, 9443]);
const httpPorts = new Set([80, 81, 3000, 5000, 8000, 8008, 8080, 8081, 8123, 8888, 9000, 9090, 10000, 32400]);

/** A product and version from a banner or Server header, when it names one. */
export function identify(text) {
  const t = String(text ?? "");
  /** @type {[RegExp, string][]} */
  const patterns = [
    [/SSH-[\d.]+-OpenSSH_([\w.]+)/, "OpenSSH"], [/SSH-[\d.]+-dropbear_([\w.]+)/i, "Dropbear SSH"],
    [/\bnginx\/([\d.]+)/i, "nginx"], [/\bApache\/([\d.]+)/, "Apache httpd"], [/\blighttpd\/([\d.]+)/i, "lighttpd"], [/\bCaddy\b/, "Caddy"],
    [/Microsoft-IIS\/([\d.]+)/, "Microsoft IIS"], [/\bvsFTPd ([\d.]+)/i, "vsftpd"], [/ProFTPD ([\d.]+)/, "ProFTPD"], [/Pure-FTPd/, "Pure-FTPd"],
    [/\bPostfix\b/, "Postfix"], [/\bExim ([\d.]+)/, "Exim"], [/\bjetty\(([\d.]+)/i, "Jetty"], [/\bmini_httpd\/([\d.]+)/, "mini_httpd"],
    [/\bBoa\/([\d.]+)/, "Boa"], [/\bGoAhead\b/i, "GoAhead"], [/\bmicro_httpd\b/, "micro_httpd"], [/\bOpenResty\/([\d.]+)/i, "OpenResty"],
    [/\bAirTunes\/([\d.]+)/, "AirPlay receiver"], [/^RFB (\d+\.\d+)/m, "VNC server (RFB)"], [/\bPlex Media Server\b/, "Plex Media Server"], [/\bCUPS\/([\d.]+)/, "CUPS"], [/\bWebs\b/, "GoAhead Webs"],
  ];
  for (const [re, product] of patterns) {
    const m = re.exec(t);
    if (m) return { product, version: m[1] ?? null };
  }
  return null;
}

function connect(ip, port, timeoutMs) {
  return new Promise((resolve) => {
    const socket = net.connect({ host: ip, port });
    const done = (ok) => { if (!ok) socket.destroy(); resolve(ok ? socket : null); };
    socket.setTimeout(timeoutMs, () => done(false));
    socket.once("connect", () => { socket.setTimeout(0); done(true); });
    socket.once("error", () => done(false));
  });
}

/** Reads what a server says first, or what it answers to `hello`, for up to `ms`. */
function exchange(socket, hello, ms) {
  return new Promise((resolve) => {
    let data = "";
    const finish = () => { socket.destroy(); resolve(data.slice(0, 2048)); };
    const timer = setTimeout(finish, ms);
    socket.on("data", (chunk) => { data += chunk.toString("latin1"); if (data.length > 2048 || /\r?\n\r?\n/.test(data)) { clearTimeout(timer); finish(); } });
    socket.once("error", () => { clearTimeout(timer); finish(); });
    socket.once("end", () => { clearTimeout(timer); finish(); });
    if (hello) socket.write(hello);
  });
}

const head = (ip) => `HEAD / HTTP/1.0\r\nHost: ${ip}\r\nUser-Agent: TheySpy\r\n\r\n`;

async function tlsDetails(ip, port, ms) {
  return new Promise((resolve) => {
    const socket = tls.connect({ host: ip, port, rejectUnauthorized: false, servername: net.isIP(ip) ? undefined : ip, ALPNProtocols: ["http/1.1"] });
    const timer = setTimeout(() => { socket.destroy(); resolve(null); }, ms);
    socket.once("secureConnect", async () => {
      const cert = socket.getPeerCertificate();
      const info = { protocol: socket.getProtocol(), subject: cert?.subject?.CN ?? null, issuer: cert?.issuer?.O ?? cert?.issuer?.CN ?? null, validTo: cert?.valid_to ?? null, selfSigned: Boolean(cert?.issuer && cert?.subject && cert.issuer.CN === cert.subject.CN) };
      const answer = port === 993 || port === 995 || port === 8883 ? "" : await exchange(socket, head(ip), Math.max(500, ms - 500));
      clearTimeout(timer);
      resolve({ tls: info, banner: answer });
    });
    socket.once("error", () => { clearTimeout(timer); resolve(null); });
  });
}

/**
 * What listens on one port: its service, banner, product and version, TLS certificate, and a risk
 * note when the port is one to worry about. Null when nothing accepts the connection.
 * @param {string} ip @param {number} port @param {{ timeoutMs?: number, bannerMs?: number }} [options]
 */
export async function checkPort(ip, port, { timeoutMs = 900, bannerMs = 1500 } = {}) {
  const socket = await connect(ip, port, timeoutMs);
  if (!socket) return null;
  const service = commonPorts[port] ?? null;
  let banner;
  let tlsInfo = null;
  if (tlsPorts.has(port)) {
    socket.destroy();
    const details = await tlsDetails(ip, port, bannerMs + 500);
    tlsInfo = details?.tls ?? null;
    banner = details?.banner ?? "";
  } else {
    banner = await exchange(socket, httpPorts.has(port) ? head(ip) : null, bannerMs);
    // A silent server on a port that is not known to be HTTP may still speak it.
    if (!banner && !service?.startsWith("http")) {
      const again = await connect(ip, port, timeoutMs);
      if (again) banner = await exchange(again, head(ip), bannerMs);
    }
  }
  const serverHeader = /^server:\s*(.+)$/im.exec(banner)?.[1]?.trim() ?? null;
  const firstLine = banner.split(/\r?\n/)[0]?.trim() ?? "";
  const summary = serverHeader ?? (/^HTTP\//.test(firstLine) ? null : firstLine.replace(/[^\x20-\x7e]/g, "").slice(0, 160)) ?? null;
  const found = identify(serverHeader ?? banner);
  return {
    port, proto: "tcp", service: /^HTTP\/\d/.test(firstLine) && !service ? "http" : service,
    banner: summary || null, product: found?.product ?? null, version: found?.version ?? null, tls: tlsInfo,
    risk: riskyPorts[port] ?? null,
  };
}

/**
 * Checks many ports on one host, a few at a time.
 * @param {string} ip @param {number[]} ports @param {{ concurrency?: number, check?: typeof checkPort, onProgress?: (done: number) => void }} [options]
 */
export async function checkPorts(ip, ports, { concurrency = 48, check = checkPort, onProgress = () => {} } = {}) {
  const open = [];
  let next = 0;
  let done = 0;
  await Promise.all(Array.from({ length: Math.min(concurrency, ports.length) }, async () => {
    while (next < ports.length) {
      const port = ports[next++];
      const result = await check(ip, port);
      if (result) open.push(result);
      done += 1;
      if (done % 128 === 0) onProgress(done);
    }
  }));
  return open.sort((a, b) => a.port - b.port);
}

/** The ports each profile checks. Quick checks none: it only sees whether the host is up. */
export const profiles = Object.freeze({
  quick: { label: "Quick", ports: [] },
  standard: { label: "Standard", ports: Object.keys(commonPorts).map(Number) },
  deep: { label: "Deep", ports: [...new Set([...Array.from({ length: 1024 }, (_, i) => i + 1), ...Object.keys(commonPorts).map(Number)])].sort((a, b) => a - b) },
});
