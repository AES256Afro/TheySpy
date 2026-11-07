import { useEffect, useState } from "react";
import { api } from "../api.ts";
import { Link } from "../router.tsx";

// One device, every tab (M15, mock-up B): evidence, exposure, CVEs, DNS activity, ports, history.

type Device = {
  id: number; name: string; nameFrom: string; ip: string | null; mac: string | null; hostname: string | null; vendor: string | null; label: string | null; owner: string | null; kind: string | null; notes: string | null;
  tags: string[]; trusted: boolean; firstSeen: string; lastSeen: string; sources: Record<string, string>; randomisedMac: boolean; online: boolean; isNew: boolean;
  names: Record<string, string | undefined>; network: { kind: string; label: string; detail: string } | null; guess: { label: string; from: string } | null;
  homeIp: string | null; tailscaleIp: string | null; addressHistory: { ip: string; firstSeen: string; lastSeen: string }[]; events: { id: number; at: string; kind: string; detail: Record<string, unknown> }[];
};
type Factor = { id: string; label: string; state: "pass" | "partial" | "fail" | "unknown" | "na"; evidence: string; fix: string };
type Finding = { id: number; deviceId: number | null; source: string; kind: string; indicator: string | null; where?: string | null; at: string; status: string; note?: string | null };
type Cve = { cveId: string; name?: string | null; kev?: boolean; score?: number | null; software: string[]; decision: { status: string; contradicted: boolean } | null };
type Service = { port: number; proto: string; service: string | null; product: string | null; version: string | null; risk: string | null; lastSeen: string };
type Activity = { connected: boolean; total: number; blockedTotal?: number; top: { domain: string; queries: number }[]; blocked: { domain: string; blocked: number; lists: string[] }[] };

const tabs = ["evidence", "exposure", "cves", "dns", "ports", "history"] as const;
type Tab = (typeof tabs)[number];
const tabLabel: Record<Tab, string> = { evidence: "Evidence", exposure: "Exposure", cves: "CVEs", dns: "DNS activity", ports: "Ports", history: "History" };
const mark = { pass: "✓", partial: "!", fail: "✕", unknown: "?", na: "–" } as const;
const markBadge = { pass: "b-ok", partial: "b-med", fail: "b-crit", unknown: "b-info", na: "" } as const;
const when = (iso: string) => new Date(iso).toLocaleString();
const eventText: Record<string, (d: Record<string, unknown>) => string> = {
  new: (d) => `New device at ${d.ip}`, inventoried: () => "First inventory", ip_changed: (d) => `Address ${d.from} → ${d.to}`, name_changed: (d) => `Name ${d.from} → ${d.to}`, merged: (d) => `Merged with the record seen at ${d.ip}`,
};

export function DeviceScreen({ id }: { id: number }) {
  const [device, setDevice] = useState<Device | null>(null);
  const [tab, setTab] = useState<Tab>("evidence");
  const [error, setError] = useState("");
  const [factors, setFactors] = useState<Factor[] | null>(null);
  const [findings, setFindings] = useState<Finding[] | null>(null);
  const [cves, setCves] = useState<{ cves: Cve[]; open: number; exploited: number } | null>(null);
  const [services, setServices] = useState<Service[] | null>(null);
  const [activity, setActivity] = useState<Activity | null>(null);

  useEffect(() => {
    setDevice(null); setFactors(null); setFindings(null); setCves(null); setServices(null); setActivity(null);
    api<{ device: Device }>("GET", `/api/fleet/devices/${id}`).then((r) => setDevice(r.device), (e: Error) => setError(e.message));
    api<{ devices: { id: number; factors: Factor[] }[] }>("GET", "/api/exposure").then((r) => setFactors(r.devices.find((d) => d.id === id)?.factors ?? []), () => setFactors([]));
    api<{ findings: Finding[] }>("GET", "/api/evidence").then((r) => setFindings(r.findings.filter((f) => f.deviceId === id)), () => setFindings([]));
    api<{ cves: Cve[]; open: number; exploited: number }>("GET", `/api/fleet/devices/${id}/cves`).then(setCves, () => setCves({ cves: [], open: 0, exploited: 0 }));
    api<{ services: Service[] }>("GET", `/api/fleet/devices/${id}/services`).then((r) => setServices(r.services), () => setServices([]));
    api<Activity>("GET", `/api/fleet/devices/${id}/activity`).then(setActivity, () => setActivity(null));
  }, [id]);

  if (error) return <div className="stack"><h1>Device</h1><div className="banner bad">{error}</div><Link href="/fleet">Fleet</Link></div>;
  if (!device) return <div className="stack"><h1>Device</h1><p className="muted small">Loading…</p></div>;
  const d = device;
  const contacts = (findings ?? []).filter((f) => f.kind === "contacted" && f.status === "open");
  const failing = (factors ?? []).filter((f) => f.state === "fail").length;
  const count: Record<Tab, number | null> = { evidence: findings ? contacts.length : null, exposure: factors ? failing : null, cves: cves ? cves.open : null, dns: activity?.total ?? null, ports: services?.length ?? null, history: d.events.length };

  return (
    <div className="stack">
      <div className="top">
        <div>
          <div className="small muted"><Link href="/fleet">Fleet</Link> / device {d.id}</div>
          <h1>{d.name}{contacts.length > 0 && <span className="badge b-crit" style={{ marginLeft: 10, verticalAlign: "middle" }}>indicator contact</span>}{d.isNew && <span className="badge b-high" style={{ marginLeft: 10, verticalAlign: "middle" }}>new</span>}</h1>
        </div>
        <div className="grow" />
        {d.ip && <Link className="btn" href={`/check?q=${encodeURIComponent(d.ip)}`}>Check</Link>}
      </div>
      <div className="facts">
        <div><b className="mono">{d.ip ?? "—"}</b><span>{d.homeIp && d.tailscaleIp ? `home · tailscale ${d.tailscaleIp}` : d.network?.label ?? "address"}</span></div>
        <div><b className="mono">{d.mac ?? "no MAC"}</b><span>{d.vendor ?? (d.randomisedMac ? "private MAC" : "vendor unknown")}</span></div>
        <div><b>{d.kind ?? d.guess?.label ?? "kind unknown"}</b><span>{d.owner ? `owner ${d.owner}` : "name from " + d.nameFrom}</span></div>
        <div><b>{d.trusted ? "trusted" : "not trusted"}</b><span>seen since {new Date(d.firstSeen).toLocaleDateString()} · {d.online ? "online" : `last ${when(d.lastSeen)}`}</span></div>
      </div>
      <div className="tabs" role="tablist">{tabs.map((t) => <button key={t} type="button" role="tab" aria-selected={tab === t} onClick={() => setTab(t)}>{tabLabel[t]}{count[t] !== null && count[t] !== 0 ? <span className={`n ${t === "evidence" && contacts.length ? "bad" : t === "exposure" && failing ? "bad" : ""}`}>{count[t]}</span> : null}</button>)}</div>

      {tab === "evidence" && (
        <section className="card stack">
          {findings === null ? <p className="small muted">Loading…</p> : findings.length === 0 ? <p className="small muted">No findings recorded for this device. Sources: the agent, MVT imports, network logs, Pi-hole history (shown under DNS activity).</p> : (
            <div className="list small">{findings.map((f) => <div key={f.id} style={{ alignItems: "flex-start" }}><span className={`badge ${f.kind === "contacted" ? "b-crit" : "b-info"}`}>{f.kind}</span><span className="grow"><span className="mono">{f.indicator ?? "—"}</span>{f.where ? <span className="muted"> · {f.where}</span> : null}<div className="muted">{f.source} · {when(f.at)} · {f.status}{f.note ? ` · ${f.note}` : ""}</div></span></div>)}</div>
          )}
          <p className="small muted"><Link href="/evidence">Evidence locker</Link> for imports and the agent.</p>
        </section>
      )}
      {tab === "exposure" && (
        <section className="card">
          {factors === null ? <p className="small muted">Loading…</p> : factors.length === 0 ? <p className="small muted">No checks apply (containers and the router are not scored).</p> : (
            <div className="list small">{factors.map((f) => <div key={f.id} style={{ alignItems: "flex-start" }}><span className={`badge ${markBadge[f.state]}`}>{mark[f.state]}</span><span className="grow"><b>{f.label}</b><br /><span className="muted">{f.evidence}</span>{f.state !== "pass" && f.state !== "na" && <><br /><span>Fix: {f.fix}</span></>}</span></div>)}</div>
          )}
        </section>
      )}
      {tab === "cves" && (
        <section className="card">
          {cves === null ? <p className="small muted">Loading…</p> : cves.cves.length === 0 ? <p className="small muted">No CVEs matched. Matching needs a software version: a Standard check (service banners), the agent, Protec, or the profile.</p> : (
            <div className="table-wrap"><table>
              <thead><tr><th>CVE</th><th>Software</th><th>Exploited</th><th>Decision</th></tr></thead>
              <tbody>{cves.cves.map((c) => <tr key={c.cveId}><td className="mono"><a href={`https://nvd.nist.gov/vuln/detail/${c.cveId}`} target="_blank" rel="noreferrer noopener">{c.cveId}</a><div className="muted small">{c.name ?? ""}</div></td><td className="small">{c.software.join("; ")}</td><td>{c.kev ? <span className="badge b-crit">KEV</span> : <span className="muted">—</span>}</td><td className="small">{c.decision ? `${c.decision.status}${c.decision.contradicted ? " (still present)" : ""}` : "open"}</td></tr>)}</tbody>
            </table></div>
          )}
        </section>
      )}
      {tab === "dns" && (
        <section className="card">
          {activity === null ? <p className="small muted">Loading…</p> : !activity.connected ? <p className="small muted">Pi-hole is not connected.</p> : activity.total === 0 ? <p className="small muted">No lookups from this device's addresses in the last 24 hours.</p> : (
            <div className="grid g2">
              <div><h3>Most looked up · 24 h · {activity.total.toLocaleString()} lookups</h3><div className="list small">{activity.top.map((t) => <div key={t.domain}><span className="grow mono">{t.domain}</span><span className="muted">{t.queries}</span></div>)}</div></div>
              <div><h3>Blocked · {activity.blockedTotal?.toLocaleString() ?? 0}</h3><div className="list small">{activity.blocked.map((b) => <div key={b.domain}><span className="grow"><span className="mono">{b.domain}</span>{b.lists.length ? <span className="muted"> · {b.lists.join(", ")}</span> : null}</span><span className="muted">{b.blocked}</span></div>)}{activity.blocked.length === 0 && <div className="muted">nothing blocked</div>}</div></div>
            </div>
          )}
        </section>
      )}
      {tab === "ports" && (
        <section className="card">
          {services === null ? <p className="small muted">Loading…</p> : services.length === 0 ? <p className="small muted">No open ports recorded. Run a Standard or Deep check.</p> : (
            <div className="table-wrap"><table>
              <thead><tr><th>Port</th><th>Service</th><th>Product</th><th>Risk</th><th>Last confirmed</th></tr></thead>
              <tbody>{services.map((s) => <tr key={`${s.proto}-${s.port}`}><td className="mono">{s.port}/{s.proto}</td><td>{s.service ?? "—"}</td><td className="small">{s.product ? `${s.product} ${s.version ?? ""}` : "—"}</td><td className="small">{s.risk ?? "—"}</td><td className="small muted">{when(s.lastSeen)}</td></tr>)}</tbody>
            </table></div>
          )}
        </section>
      )}
      {tab === "history" && (
        <section className="card grid g2">
          <div><h3>Addresses</h3><div className="list small">{d.addressHistory.map((a) => <div key={a.ip}><span className="grow mono">{a.ip}</span><span className="muted">{when(a.lastSeen)}</span></div>)}</div></div>
          <div><h3>Events</h3><div className="list small">{d.events.map((e) => <div key={e.id}><span className="grow">{(Object.hasOwn(eventText, e.kind) ? eventText[e.kind] : () => e.kind)(e.detail)}</span><span className="muted">{when(e.at)}</span></div>)}</div></div>
        </section>
      )}
    </div>
  );
}
