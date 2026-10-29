import { useCallback, useEffect, useState, type FormEvent } from "react";
import { api, lastLogLine, waitForJob } from "../api.ts";

type Service = { port: number; proto: string; service: string | null; product: string | null; version: string | null; banner: string | null; tls: { protocol: string; subject: string | null; issuer: string | null; validTo: string | null; selfSigned: boolean } | null; risk: string | null; lastSeen?: string };
type Hit = { domain: string; indicator: string; lookups: number; lastAt: string; lastStatus: string; citation?: { label: string } | null };
type DeviceInfo = { id: number; name: string; ip: string | null; mac: string | null; hostname: string | null; vendor: string | null; owner: string | null; kind: string | null; tags: string[]; trusted: boolean; firstSeen: string; lastSeen: string; randomisedMac: boolean; events: { id: number; at: string; kind: string; detail: Record<string, unknown> }[] };
type WebCve = { cveId: string; cvss: number | null; severity: string | null; description: string | null; kev: boolean; epss: number | null };
type WebSoftware = { product: string; version: string | null; source: string; supportEnds?: string | null; supported?: boolean | null; cves?: WebCve[]; cvesError?: string };
type WebFinding = { path: string; severity: "critical" | "high" | "medium" | "low"; title: string; evidence: string; fix: string };
type Check = {
  id: number; query: string; kind: "device" | "domain" | "network" | "website"; profile: string; durationMs: number;
  url?: string; access?: string; software?: WebSoftware[]; findings?: WebFinding[];
  ip?: string; up?: boolean | null; open?: Service[] | null; services?: Service[]; device?: DeviceInfo | null;
  dns?: { connected: boolean; error?: string; hits: Hit[]; totalLookups: number; topDomains: { domain: string; queries: number; blocked: number }[] };
  domain?: string; days?: number; lookups?: number; indicator?: boolean; clients?: { ip: string; device: string | null; lookups: number; blocked: number; first: string; last: string; names: string[] }[];
  network?: string; sweep?: { alive: number; withMac: number; newDevices: number }; devices?: { id: number; name: string; ip: string; mac: string | null; vendor: string | null; online: boolean }[];
};
type Recent = { id: number; query: string; kind: string; profile: string; startedAt: string; finishedAt: string | null };
type Profile = { id: string; label: string; ports: number };

const profileHelp: Record<string, string> = {
  quick: "Is it up? One probe, its MAC and name. Works for a whole network too.",
  standard: "Also checks the ports homes use, and reads what answers to name the product and version.",
  deep: "Every port up to 1024 plus the usual ones. Takes longer.",
  dns: "Sends nothing: what Pi-hole saw it look up.",
};
const when = (iso: string) => new Date(iso).toLocaleString();

export function CheckScreen() {
  const [query, setQuery] = useState(() => new URLSearchParams(location.search).get("q") ?? "");
  const [profile, setProfile] = useState("standard");
  const [profiles, setProfiles] = useState<Profile[]>([]);
  const [ranges, setRanges] = useState<string[]>([]);
  const [recent, setRecent] = useState<Recent[]>([]);
  const [check, setCheck] = useState<Check | null>(null);
  const [busy, setBusy] = useState("");
  const [error, setError] = useState("");

  const loadRecent = useCallback(async () => {
    const r = await api<{ checks: Recent[]; profiles: Profile[]; scanRanges: string[] }>("GET", "/api/fleet/checks");
    setRecent(r.checks);
    setProfiles(r.profiles);
    setRanges(r.scanRanges);
  }, []);
  useEffect(() => { loadRecent().catch((e: Error) => setError(e.message)); }, [loadRecent]);
  const show = async (id: number) => setCheck((await api<{ check: Check }>("GET", `/api/fleet/checks/${id}`)).check);

  const submit = async (e?: FormEvent) => {
    e?.preventDefault();
    setError("");
    setBusy("Starting…");
    try {
      const { job } = await api<{ job: { id: number } }>("POST", "/api/fleet/check", { query, profile });
      setBusy("Checking…");
      const done = await waitForJob(job.id);
      if (done.status !== "succeeded") throw new Error(lastLogLine(done) || "The check failed");
      const checkId = (done.result as { checkId?: number } | null)?.checkId;
      if (checkId) await show(checkId);
      await loadRecent();
    } catch (err) {
      setError(err instanceof Error ? err.message : String(err));
    } finally {
      setBusy("");
    }
  };

  return (
    <div className="stack">
      <div className="top"><div><h1>Targeted check</h1><p className="muted small">An address, MAC, hostname, network or domain. Active checks stay inside {ranges.join(", ") || "your scan ranges"}; a domain is only looked up in Pi-hole’s history.</p></div></div>
      <form className="card stack" onSubmit={submit}>
        <div className="row">
          <input className="input grow" style={{ minWidth: 220 }} value={query} onChange={(e) => setQuery(e.target.value)} placeholder="192.168.1.42 · a4:c1:38:… · nas · 192.168.1.0/24 · example.com · https://your-site" aria-label="What to check" required />
          <button className="btn primary" type="submit" disabled={Boolean(busy)}>{busy ? "Checking…" : "Check"}</button>
        </div>
        <div className="seg" role="group" aria-label="Profile">{profiles.map((p) => (
          <button key={p.id} type="button" aria-pressed={profile === p.id} title={profileHelp[p.id]} onClick={() => setProfile(p.id)}>{p.label}{p.ports ? ` · ${p.ports} ports` : ""}</button>
        ))}</div>
        <p className="small muted">{/^https?:\/\//i.test(query.trim()) ? "A website address runs the website check: its PHP and CMS versions, their CVEs, and files that should not be public. Only GET requests to a fixed list of paths. A public site must be yours: the first check tells you how to prove it." : profileHelp[profile]}</p>
      </form>
      {error && <div className="banner bad" role="alert"><span className="small">{error}</span></div>}

      {check?.kind === "device" && <DeviceResult check={check} />}
      {check?.kind === "domain" && <DomainResult check={check} />}
      {check?.kind === "website" && <WebsiteResult check={check} />}
      {check?.kind === "network" && (
        <section className="card stack">
          <header><h2>{check.network}</h2><span className="muted small">{check.sweep?.alive} answered · {check.sweep?.newDevices} new · {(check.durationMs / 1000).toFixed(1)} s</span></header>
          <div className="list small">{(check.devices ?? []).map((d) => <div key={d.id}><span className={`dot ${d.online ? "on" : ""}`} /><span className="grow"><b>{d.name}</b> <span className="muted">{d.vendor ?? ""}</span></span><span className="mono">{d.ip}</span></div>)}</div>
        </section>
      )}

      {recent.length > 0 && (
        <section className="card">
          <header><h2>Recent checks</h2></header>
          <div className="list small">{recent.map((r) => (
            <div key={r.id}><button type="button" className="linkish grow" onClick={() => void show(r.id)}><b className="mono">{r.query}</b></button><span className="muted">{r.kind} · {r.profile}</span><span className="muted">{when(r.startedAt)}</span></div>
          ))}</div>
        </section>
      )}
    </div>
  );
}

function DeviceResult({ check }: { check: Check }) {
  const d = check.device;
  const services = check.services ?? [];
  return (
    <div className="two-col">
      <div className="stack">
        <section className="card stack">
          <header><h2>Services {check.open === null ? "(not checked)" : ""}</h2><span className="muted small">{check.profile} · {(check.durationMs / 1000).toFixed(1)} s · {check.up === null ? "no packets sent" : check.up ? "up" : "did not answer"}</span></header>
          {services.length === 0 ? <p className="small muted">{check.open === null ? "DNS only: nothing was sent to the device." : "Nothing listening on the ports checked. Phones and many IoT devices listen on none."}</p> : (
            <div className="table-wrap"><table>
              <thead><tr><th>Port</th><th>Service</th><th>Product</th><th>What it said</th></tr></thead>
              <tbody>{services.map((s) => (
                <tr key={`${s.port}/${s.proto}`}>
                  <td className="mono">{s.port}</td>
                  <td>{s.service ?? "—"}{s.risk && <div><span className="badge b-high" title={s.risk}>look at this</span></div>}</td>
                  <td>{s.product ? <b>{s.product}{s.version ? ` ${s.version}` : ""}</b> : <span className="muted">unknown</span>}{s.tls && <div className="muted small">TLS {s.tls.protocol}{s.tls.subject ? ` · ${s.tls.subject}` : ""}{s.tls.selfSigned ? " · self-signed" : s.tls.issuer ? ` · ${s.tls.issuer}` : ""}</div>}</td>
                  <td className="small">{s.risk ? <span>{s.risk}<br /></span> : null}<span className="mono muted">{s.banner ?? ""}</span></td>
                </tr>
              ))}</tbody>
            </table></div>
          )}
        </section>
        <section className="card stack">
          <header><h2>Pi-hole’s view</h2>{check.dns?.connected && <span className="muted small">{check.dns.totalLookups.toLocaleString()} lookups in 7 days</span>}</header>
          {!check.dns?.connected ? <p className="small muted">Connect Pi-hole to see what this device looks up.</p> : check.dns.error ? <p className="small muted">{check.dns.error}</p> : (
            <>
              {check.dns.hits.length > 0 ? (
                <div className="banner bad"><span className="small"><b>Indicator lookups.</b> {check.dns.hits.map((h) => `${h.domain} (${h.lookups}×, last ${when(h.lastAt)}, ${h.lastStatus.toLowerCase()})`).join("; ")}. A DNS record shows the device asked for the name; it does not prove infection. For a phone, run MVT with TheySpy’s STIX bundle (Indicators).</span></div>
              ) : <p className="small muted">No lookups of spyware or ad-intelligence indicators.</p>}
              <div className="list small">{check.dns.topDomains.map((t) => <div key={t.domain}><span className="grow mono">{t.domain}</span><span className="muted">{t.queries}{t.blocked ? ` · ${t.blocked} blocked` : ""}</span></div>)}</div>
            </>
          )}
        </section>
      </div>
      <div className="stack sticky">
        <section className="card stack">
          <h3>{d ? d.name : check.ip}</h3>
          {d ? (
            <div className="list small">
              <div><span className="grow muted">Address</span><span className="mono">{d.ip}</span></div>
              <div><span className="grow muted">MAC</span><span className="mono">{d.mac ?? "not known"}{d.randomisedMac ? " (private)" : ""}</span></div>
              {d.hostname && <div><span className="grow muted">Name</span><span className="mono">{d.hostname}</span></div>}
              <div><span className="grow muted">Vendor</span><span>{d.vendor ?? "unknown"}</span></div>
              {d.owner && <div><span className="grow muted">Owner</span><span>{d.owner}</span></div>}
              <div><span className="grow muted">First seen</span><span>{when(d.firstSeen)}</span></div>
              <div><span className="grow muted">Trusted</span><span>{d.trusted ? "yes" : "no"}</span></div>
            </div>
          ) : <p className="small muted">Not in the fleet: it has not answered or been seen by Pi-hole.</p>}
          {d && <a className="small" href="/fleet">Open in Fleet</a>}
        </section>
        {d && d.events.length > 0 && (
          <section className="card stack">
            <h3>Timeline</h3>
            <div className="list small">{d.events.slice(0, 10).map((e) => <div key={e.id}><span className="grow">{e.kind.replace("_", " ")}{typeof e.detail.ip === "string" ? ` · ${e.detail.ip}` : ""}{typeof e.detail.to === "string" ? ` → ${e.detail.to}` : ""}</span><span className="muted">{when(e.at)}</span></div>)}</div>
          </section>
        )}
      </div>
    </div>
  );
}

function DomainResult({ check }: { check: Check }) {
  return (
    <section className="card stack">
      <header><h2 className="mono">{check.domain}</h2><span className="muted small">{check.lookups} lookups in {check.days} days · Pi-hole’s history only</span></header>
      {check.indicator && <div className="banner bad"><span className="small">This name is a spyware or ad-intelligence indicator.</span></div>}
      {(check.clients ?? []).length === 0 ? <p className="small muted">No device looked it up in the last {check.days} days.</p> : (
        <div className="table-wrap"><table>
          <thead><tr><th>Device</th><th>Lookups</th><th>Blocked</th><th>First</th><th>Last</th><th>Names</th></tr></thead>
          <tbody>{(check.clients ?? []).map((c) => (
            <tr key={c.ip}><td><b>{c.device ?? c.ip}</b><div className="mono muted small">{c.ip}</div></td><td className="mono">{c.lookups}</td><td className="mono">{c.blocked}</td><td className="small">{when(c.first)}</td><td className="small">{when(c.last)}</td><td className="mono small">{c.names.join(", ")}</td></tr>
          ))}</tbody>
        </table></div>
      )}
    </section>
  );
}

const findingBadge: Record<string, string> = { critical: "b-crit", high: "b-high", medium: "b-med", low: "b-low" };

function WebsiteResult({ check }: { check: Check }) {
  const findings = check.findings ?? [];
  return (
    <div className="stack">
      <section className="card stack">
        <header><h2 className="mono">{check.url}</h2><span className="muted small">{check.access} · {(check.durationMs / 1000).toFixed(1)} s</span></header>
        {findings.length === 0 ? <p className="small muted">Nothing exposed on the paths checked.</p> : (
          <div className="list">{findings.map((f, i) => (
            <div key={`${f.path}-${i}`} style={{ alignItems: "flex-start" }}>
              <span className={`badge ${findingBadge[f.severity]}`}>{f.severity}</span>
              <span className="grow stack" style={{ gap: 2 }}><b className="small">{f.title}</b><span className="small muted mono">{f.path} · {f.evidence}</span><span className="small">{f.fix}</span></span>
            </div>
          ))}</div>
        )}
      </section>
      {(check.software ?? []).map((s) => (
        <section key={s.product} className="card stack">
          <header>
            <h2>{s.product} {s.version ?? <span className="muted">(version hidden)</span>}</h2>
            <span className="muted small">from {s.source}{s.supportEnds ? ` · security support ${s.supported ? "until" : "ended"} ${s.supportEnds}` : ""}</span>
          </header>
          {!s.version ? <p className="small muted">The version is not visible, so CVEs cannot be matched. That is good practice; check the version on the server itself.</p>
            : s.cvesError ? <p className="small muted">Could not ask NVD: {s.cvesError}</p>
            : !s.cves?.length ? <p className="small muted">NVD lists no CVEs for this version.</p> : (
              <div className="table-wrap"><table>
                <thead><tr><th>CVE</th><th>CVSS</th><th>Exploited</th><th>What</th></tr></thead>
                <tbody>{s.cves.slice(0, 50).map((c) => (
                  <tr key={c.cveId}>
                    <td className="mono"><a href={`https://nvd.nist.gov/vuln/detail/${c.cveId}`} target="_blank" rel="noreferrer noopener">{c.cveId}</a></td>
                    <td>{c.cvss ?? "—"}</td>
                    <td>{c.kev ? <span className="badge b-crit">KEV</span> : ""}</td>
                    <td className="small">{c.description}</td>
                  </tr>
                ))}</tbody>
              </table></div>
            )}
          {(s.cves?.length ?? 0) > 50 && <p className="small muted">Showing 50 of {s.cves?.length}, exploited and highest scores first.</p>}
        </section>
      ))}
    </div>
  );
}
