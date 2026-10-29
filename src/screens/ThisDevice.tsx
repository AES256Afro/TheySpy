import { useCallback, useEffect, useState } from "react";
import { api } from "../api.ts";

type Cve = { cveId: string; cvss: number | null; description: string | null; fixed: string | null; kev: boolean; kevDue: string | null; epss: number | null };
type Result = {
  browser: { name: string; version: string; exact: boolean; source: string } | null;
  os: string | null; gpc: boolean; adBlocked: boolean; clientIp: string;
  dns: { checked: boolean; throughPihole?: boolean; from?: string | null; error?: string };
  device: { id: number; name: string; ip: string } | null;
  cves: Cve[] | null; cvesError: string | null; exploited: number | null;
};
type UaData = { getHighEntropyValues?: (hints: string[]) => Promise<Record<string, unknown>> };

/** Runs a probe: true when the request went through, false when it was blocked or failed. */
async function reaches(url: string, ms = 4000) {
  try {
    await fetch(url, { mode: "no-cors", cache: "no-store", signal: AbortSignal.timeout(ms) });
    return true;
  } catch {
    return false;
  }
}

export function ThisDeviceScreen() {
  const [result, setResult] = useState<Result | null>(null);
  const [step, setStep] = useState("");
  const [error, setError] = useState("");
  const [confirm, setConfirm] = useState("");

  const run = useCallback(async (confirmedVersion?: string) => {
    setError("");
    try {
      setStep("Reading your browser…");
      const ua = (navigator as Navigator & { userAgentData?: UaData }).userAgentData;
      const uaData = ua?.getHighEntropyValues ? await ua.getHighEntropyValues(["platform", "platformVersion", "fullVersionList", "model", "mobile", "architecture"]).catch(() => null) : null;
      const begun = await api<{ token: string; dnsName: string; adProbeUrl: string }>("POST", "/api/this-device/start");
      setStep("Probing ad blocking and DNS…");
      const [adLoaded] = await Promise.all([reaches(begun.adProbeUrl), reaches(`http://${begun.dnsName}/`, 2500)]);
      setStep("Looking for the test name in Pi-hole’s log…");
      await new Promise((r) => setTimeout(r, 4000)); // Pi-hole's API shows a query a few seconds after it
      const gpc = Boolean((navigator as Navigator & { globalPrivacyControl?: boolean }).globalPrivacyControl);
      setResult(await api<Result>("POST", "/api/this-device/check", { token: begun.token, userAgent: navigator.userAgent, uaData, gpc, adBlocked: !adLoaded, confirmedVersion }));
    } catch (e) {
      setError(e instanceof Error ? e.message : String(e));
    } finally {
      setStep("");
    }
  }, []);
  useEffect(() => { void run(); }, [run]);

  const b = result?.browser;
  return (
    <div className="stack">
      <div className="top">
        <div><h1>This device</h1><p className="muted small">What applies to the browser you are reading this in. Nothing is saved.</p></div>
        <div className="grow" />
        <button className="btn primary" type="button" disabled={Boolean(step)} onClick={() => void run(confirm || undefined)}>{step ? "Checking…" : "Check again"}</button>
      </div>
      {step && <p className="small muted">{step}</p>}
      {error && <div className="banner bad"><span className="small">{error}</span></div>}

      {result && (
        <div className="two-col">
          <div className="stack">
            <section className="card stack">
              <header><h2>Vulnerabilities in this browser</h2>{result.exploited ? <span className="badge b-crit">{result.exploited} exploited</span> : null}</header>
              {!b ? <p className="small muted">TheySpy could not tell which browser this is.</p>
                : !b.exact ? (
                  <div className="stack">
                    <p className="small">{b.name === "Safari" ? "Safari does not tell web pages its exact version" : `${b.name} only shows a reduced version (${b.version}) here`}, so CVEs cannot be matched. Type the exact version (in {b.name === "Safari" ? "Safari → About Safari" : "the browser’s About page"}) and check again.</p>
                    <div className="row"><input className="input" style={{ maxWidth: 200 }} placeholder="e.g. 26.0.1" value={confirm} onChange={(e) => setConfirm(e.target.value)} aria-label="Exact browser version" />
                      <button className="btn" type="button" disabled={!confirm || Boolean(step)} onClick={() => void run(confirm)}>Use this version</button></div>
                  </div>
                ) : result.cvesError ? <p className="small muted">Could not ask NVD: {result.cvesError}</p>
                : !result.cves?.length ? <div className="banner good"><span className="small">No CVEs listed for {b.name} {b.version}.</span></div> : (
                  <>
                    <div className="list">{result.cves.slice(0, 30).map((c) => (
                      <div key={c.cveId} className="stack" style={{ alignItems: "stretch", gap: 4 }}>
                        <div className="row" style={{ gap: 8 }}>
                          <span className={`badge ${c.kev ? "b-crit" : (c.cvss ?? 0) >= 7 ? "b-high" : "b-med"}`}>{c.kev ? "EXPLOITED" : c.cvss ? `CVSS ${c.cvss}` : "CVE"}</span>
                          <a className="mono small" href={`https://nvd.nist.gov/vuln/detail/${c.cveId}`} target="_blank" rel="noreferrer noopener">{c.cveId}</a>
                          <span className="grow" />
                          {c.fixed && <span className="small muted">fixed in {c.fixed}</span>}
                        </div>
                        <span className="small muted">{c.description}{c.kev && c.kevDue ? ` CISA due date ${c.kevDue}.` : ""}</span>
                      </div>
                    ))}</div>
                    {result.cves.length > 30 && <p className="small muted">Showing 30 of {result.cves.length}, exploited first.</p>}
                    <p className="small">Update {b.name} to <b>{newest(result.cves.map((c) => c.fixed)) ?? "the latest version"}</b> or later and restart it: that fixes every CVE listed. Most updates are already downloaded and wait for a restart.</p>
                  </>
                )}
            </section>
            <section className="card stack">
              <header><h2>Ad-targeting checks</h2><span className="muted small">from Citizen Lab’s defender guidance</span></header>
              <div className="list small">
                <Check ok={result.gpc} title="Global Privacy Control" yes="On: sites are told not to sell or share your data." no="Off. Turn it on in the browser’s privacy settings (Firefox, Brave and DuckDuckGo have it; Chrome needs an extension)." />
                <Check ok={result.adBlocked} title="Ad-exchange scripts blocked" yes="Google’s ad script did not load: your DNS or a blocker stopped it." no="Google’s ad script loaded. Ads, and the targeting behind them, reach this browser." />
                {result.dns.checked
                  ? <Check ok={Boolean(result.dns.throughPihole)} title="DNS goes through Pi-hole" yes={`A one-time test name was seen in Pi-hole’s log from ${result.dns.from}.`} no="The test name never reached Pi-hole: this browser or device uses its own DNS (Chrome’s Secure DNS, iCloud Private Relay, Android Private DNS or a VPN), so Pi-hole’s blocking and TheySpy’s watch do not cover it." />
                  : <div><span className="badge b-info">?</span><span className="grow">DNS through Pi-hole: {result.dns.error ?? "connect Pi-hole to check."}</span></div>}
                <div><span className="badge b-info">?</span><span className="grow">Advertising ID: a web page cannot read it. On phones, turn off Personalized ads / delete the advertising ID (Android) or turn off Allow Apps to Request to Track (iOS).</span></div>
                <div><span className="badge b-info">?</span><span className="grow">Public IP and Starlink egress: coming in a later version.</span></div>
              </div>
            </section>
          </div>
          <div className="stack sticky">
            <section className="card stack">
              <h3>Read from your browser</h3>
              <div className="list small">
                <div><span className="grow muted">Browser</span><b>{b ? `${b.name} ${b.version}` : "unknown"}</b></div>
                <div><span className="grow muted">Version from</span><span>{b ? `${b.source}${b.exact ? "" : " (not exact)"}` : "—"}</span></div>
                <div><span className="grow muted">System</span><span>{result.os ?? "unknown"}</span></div>
                <div><span className="grow muted">Address</span><span className="mono">{result.dns.from ?? result.clientIp}</span></div>
                <div><span className="grow muted">In Fleet as</span><span>{result.device ? <a href="/fleet">{result.device.name}</a> : "not matched"}</span></div>
              </div>
            </section>
          </div>
        </div>
      )}
    </div>
  );
}

function Check({ ok, title, yes, no }: { ok: boolean; title: string; yes: string; no: string }) {
  return <div style={{ alignItems: "flex-start" }}><span className={`badge ${ok ? "b-ok" : "b-high"}`}>{ok ? "✓" : "!"}</span><span className="grow"><b>{title}</b><br /><span className="muted">{ok ? yes : no}</span></span></div>;
}

/** The highest of some dotted version numbers. */
function newest(versions: (string | null)[]) {
  const parts = (v: string) => v.split(".").map((x) => Number.parseInt(x, 10) || 0);
  return versions.filter((v): v is string => Boolean(v)).reduce<string | null>((best, v) => {
    if (!best) return v;
    const [a, b] = [parts(v), parts(best)];
    for (let i = 0; i < Math.max(a.length, b.length); i += 1) if ((a[i] ?? 0) !== (b[i] ?? 0)) return (a[i] ?? 0) > (b[i] ?? 0) ? v : best;
    return best;
  }, null);
}
