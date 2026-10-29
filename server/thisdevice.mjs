import { randomBytes } from "node:crypto";
import express from "express";

// This device (docs/PLAN.md M6, mockup 06): what applies to the browser the dashboard is open in.
// The page sends what it can read (User-Agent Client Hints, the user agent, Global Privacy Control)
// and the results of two probes it ran: whether an ad-exchange script loaded, and a lookup of a
// one-time name under dnscheck.theyspy.example that TheySpy then looks for in Pi-hole's log.

export const dnsCheckZone = "dnscheck.theyspy.example";
export const adProbeUrl = "https://pagead2.googlesyndication.com/pagead/js/adsbygoogle.js";

const chromiumBrands = [
  ["Google Chrome", "google", "chrome", "Chrome"], ["Microsoft Edge", "microsoft", "edge_chromium", "Edge"], ["Opera", "opera", "opera_browser", "Opera"],
  ["Brave", "google", "chrome", "Brave (Chromium)"], ["Chromium", "google", "chrome", "Chromium"],
];

/**
 * The browser and OS, as exactly as they can be read. `exact` is false when the version is a frozen
 * or reduced one (Chrome's user agent says 141.0.0.0; Safari's says the Safari version, not the build).
 * @param {{ userAgent?: string, uaData?: { fullVersionList?: { brand: string, version: string }[], platform?: string, platformVersion?: string, model?: string, mobile?: boolean } | null }} input
 */
export function identifyBrowser({ userAgent = "", uaData = null }) {
  let browser = null;
  for (const [brand, vendor, product, label] of chromiumBrands) {
    const hit = uaData?.fullVersionList?.find((b) => b.brand === brand);
    if (hit) { browser = { name: label, vendor, product, version: hit.version, exact: true, source: "Client Hints" }; break; }
  }
  if (!browser) {
    const ua = userAgent;
    let m;
    if ((m = /Firefox\/(\d+\.\d+(?:\.\d+)?)/.exec(ua))) browser = { name: "Firefox", vendor: "mozilla", product: "firefox", version: m[1], exact: true, source: "user agent" };
    else if ((m = /Edg\/([\d.]+)/.exec(ua))) browser = { name: "Edge", vendor: "microsoft", product: "edge_chromium", version: m[1], exact: !/\.0\.0\.0$/.test(m[1]), source: "user agent" };
    else if ((m = /Chrome\/([\d.]+)/.exec(ua))) browser = { name: "Chrome", vendor: "google", product: "chrome", version: m[1], exact: !/\.0\.0\.0$/.test(m[1]), source: "user agent" };
    else if ((m = /Version\/([\d.]+).*Safari\//.exec(ua))) browser = { name: "Safari", vendor: "apple", product: "safari", version: m[1], exact: false, source: "user agent" };
  }
  let os = null;
  const pv = uaData?.platformVersion ?? "";
  const platform = uaData?.platform ?? "";
  if (platform === "macOS" && pv) os = `macOS ${pv.split(".").slice(0, 2).join(".")}`;
  else if (platform === "Windows" && pv) os = Number(pv.split(".")[0]) >= 13 ? "Windows 11" : "Windows 10";
  else if (platform === "Android" && pv) os = `Android ${pv.split(".")[0]}${uaData?.model ? ` (${uaData.model})` : ""}`;
  else if (/iPhone OS (\d+)_(\d+)/.test(userAgent)) os = `iOS ${/iPhone OS (\d+)_(\d+)/.exec(userAgent).slice(1).join(".")}`;
  else if (/Mac OS X/.test(userAgent)) os = "macOS (version hidden by the browser)";
  else if (/Windows NT/.test(userAgent)) os = "Windows";
  else if (/Android/.test(userAgent)) os = "Android";
  else if (/Linux/.test(userAgent)) os = "Linux";
  return { browser, os };
}

/**
 * @param {{
 *   fleet: ReturnType<typeof import("./fleet/registry.mjs").createFleet>,
 *   sentinel: ReturnType<typeof import("./pihole/sentinel.mjs").createSentinel>,
 *   software: ReturnType<typeof import("./cves/lookup.mjs").createSoftwareLookup>,
 *   now?: () => Date,
 * }} deps
 */
export function thisDeviceRoutes({ fleet, sentinel, software, now = () => new Date() }) {
  const router = express.Router();
  const pending = new Map(); // token → issued at (ms); a token is good for ten minutes

  router.post("/start", (req, res) => {
    for (const [t, at] of pending) if (now().getTime() - at > 600_000) pending.delete(t);
    const token = randomBytes(6).toString("hex");
    pending.set(token, now().getTime());
    res.json({ token, dnsName: `ts-${token}.${dnsCheckZone}`, adProbeUrl, clientIp: req.ip });
  });

  router.post("/check", async (req, res) => {
    const body = req.body ?? {};
    const token = String(body.token ?? "");
    if (!pending.has(token)) return res.status(400).json({ error: "Start the check again; that token is unknown or expired" });
    const issued = pending.get(token);
    pending.delete(token);
    const { browser, os } = identifyBrowser({ userAgent: String(body.userAgent ?? req.get("user-agent") ?? ""), uaData: body.uaData ?? null });
    if (browser && body.confirmedVersion && /^[\d.]{1,30}$/.test(String(body.confirmedVersion))) Object.assign(browser, { version: String(body.confirmedVersion), exact: true, source: "confirmed by you" });

    let cves = null;
    let cvesError = null;
    if (browser?.exact) {
      try { cves = await software.lookup({ vendor: browser.vendor, product: browser.product, version: browser.version }); } catch (error) { cvesError = error.message; }
    }

    // Did this device's lookup of the one-time name reach Pi-hole?
    let dns = { checked: false };
    if (sentinel.effective().mode) {
      const name = `ts-${token}.${dnsCheckZone}`;
      try {
        const seen = await sentinel.source().lookupsOf(name, { from: issued / 1000 - 5, until: now().getTime() / 1000 + 5 });
        dns = { checked: true, throughPihole: seen.length > 0, from: seen[0]?.clientIp ?? null };
      } catch (error) {
        dns = { checked: false, error: error.message };
      }
    }
    const gpc = req.get("sec-gpc") === "1" || body.gpc === true;
    const device = fleet.list().find((d) => d.ip === (dns.from ?? req.ip)) ?? null;
    res.json({
      browser, os, gpc, adBlocked: body.adBlocked === true, dns, clientIp: req.ip,
      device: device ? { id: device.id, name: device.name, ip: device.ip } : null,
      cves, cvesError,
      exploited: cves ? cves.filter((c) => c.kev).length : null,
    });
  });
  return router;
}
