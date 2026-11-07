import { useCallback, useEffect, useState, type ReactNode } from "react";
import { api } from "../api.ts";
import type { Appearance } from "../looks/looks.ts";
import { Link } from "../router.tsx";

type Factor = { id: string; label: string; state: "pass" | "partial" | "fail" | "unknown" | "na"; evidence: string; fix: string };
type Lookup = { device: string; deviceId: number | null; clientIp: string; domain: string; indicator: string; via: string; lookups: number; blocked: number; lastSeen: string };
type Exploited = { cveId: string; device: string; deviceId: number | null; software: string; fixed: string | null };
type Gap = { deviceId: number | null; device: string | null; check: string; evidence: string; fix: string };
type Event = { at: string; action: string; tone: "bad" | "warn" | "none"; text: string; link: string | null };
type Row = { id: number; name: string; ip: string | null; kind: string | null; online: boolean; isNew: boolean; trusted: boolean; lastSeen: string; hits: number; notBlocked: number; kev: number; exposure: { known: number; of: number; score: number | null; tone: string } | null; agentAt: string | null; attention: number };
type Data = {
  at: string;
  status: { pihole: boolean; watch: boolean; devices: number; online: number };
  questions: {
    contacts: { count: number; lookups: number; top: Lookup[] };
    exploited: { count: number; devices: string[]; top: Exploited[] };
    newDevices: { count: number; names: { id: number; name: string; ip: string | null }[] };
    network: { failing: number; unknown: number; of: number; factors: Factor[] };
  };
  gaps: Gap[]; gapsTotal: number; events: Event[]; devices: Row[];
};

const when = (iso: string) => new Date(iso).toLocaleString();
const clock = (iso: string) => new Date(iso).toLocaleTimeString([], { hour: "2-digit", minute: "2-digit" });
function ago(iso: string) {
  const s = Math.max(0, (Date.now() - Date.parse(iso)) / 1000);
  if (s < 90) return "now";
  if (s < 3600) return `${Math.round(s / 60)} min`;
  if (s < 86400 * 2) return `${Math.round(s / 3600)} h`;
  return `${Math.round(s / 86400)} d`;
}
const devLink = (id: number | null, name: string) => (id === null ? <b>{name}</b> : <Link href={`/fleet/devices/${id}`}><b>{name}</b></Link>);

export function OverviewScreen({ layout }: { layout: Appearance["layout"] }) {
  const [data, setData] = useState<Data | null>(null);
  const [error, setError] = useState("");
  const load = useCallback(async () => { setData(await api<Data>("GET", "/api/overview")); setError(""); }, []);
  useEffect(() => {
    load().catch((e: Error) => setError(e.message));
    const timer = setInterval(() => { void load().catch(() => {}); }, 60_000);
    return () => clearInterval(timer);
  }, [load]);
  if (!data) return <div className="stack"><h1>Overview</h1>{error ? <div className="banner bad">{error}</div> : <p className="muted small">Loading…</p>}</div>;
  if (layout === "ledger") return <Ledger data={data} />;
  if (layout === "console") return <Console data={data} />;
  return <Verdict data={data} />;
}

/** One sentence on the current state, from the four questions. */
function sentence(q: Data["questions"], status: Data["status"]) {
  const parts: string[] = [];
  if (q.contacts.count) parts.push(`${q.contacts.count} device${q.contacts.count === 1 ? "" : "s"} reached an indicator address that was not blocked`);
  if (q.exploited.count) parts.push(`${q.exploited.count} exploited CVE${q.exploited.count === 1 ? "" : "s"} on ${q.exploited.devices.length} device${q.exploited.devices.length === 1 ? "" : "s"}`);
  if (q.newDevices.count) parts.push(`${q.newDevices.count} new device${q.newDevices.count === 1 ? "" : "s"}`);
  if (q.network.failing) parts.push(`${q.network.failing} network check${q.network.failing === 1 ? "" : "s"} failing`);
  if (!status.pihole) parts.push("Pi-hole is not connected, so new lookups are not being read");
  if (!parts.length) return "No indicator contacts, no exploited CVEs on devices, no new devices, network checks passing.";
  return `${parts.join("; ")}.`;
}

/** One of the four questions: a count, a title, what it rests on, and where to go. */
function Q({ n, mark, title, children, href }: { n: string | number; mark: "bad" | "warn" | "ok" | "none"; title: string; children: ReactNode; href: string }) {
  return (
    <section className="card q">
      <div className={`mark ${mark}`}>{n}</div>
      <div><h2>{title}</h2><div className="small muted">{children}</div></div>
      <Link className="btn" href={href}>Open</Link>
    </section>
  );
}

export function Verdict({ data }: { data: Data }) {
  const { questions: q, status } = data;
  const tone = q.contacts.count ? "bad" : q.exploited.count || q.network.failing || !status.pihole ? "warn" : "good";
  return (
    <div className="stack">
      <div className={`verdict ${tone}`}>
        <span className="small muted">{when(data.at)} · Pi-hole {status.pihole ? (status.watch ? "watching" : "connected, watch off") : "not connected"} · {status.online} of {status.devices} devices online</span>
        <h1>{sentence(q, status)}</h1>
      </div>
      <Q n={q.contacts.count} mark={q.contacts.count ? "bad" : status.pihole ? "ok" : "none"} title="Indicator contacts not blocked (7 days)" href="/pihole">
        {q.contacts.top.length ? q.contacts.top.map((l) => <div key={`${l.clientIp}-${l.domain}-${l.via}`}>{devLink(l.deviceId, l.device)} → <span className="mono">{l.indicator}</span> · {l.lookups - l.blocked} of {l.lookups} not blocked · {ago(l.lastSeen)}</div>) : status.pihole ? "None in Pi-hole's history." : "Not readable until Pi-hole is connected."}
      </Q>
      <Q n={q.exploited.count} mark={q.exploited.count ? "warn" : "ok"} title="Exploited CVEs in device software" href="/intel">
        {q.exploited.top.length ? q.exploited.top.map((e) => <div key={`${e.cveId}-${e.device}`}><span className="mono">{e.cveId}</span> · {devLink(e.deviceId, e.device)} · {e.software}{e.fixed ? ` · fixed in ${e.fixed}` : ""}</div>) : "None matched against known software versions."}
      </Q>
      <Q n={q.newDevices.count} mark={q.newDevices.count ? "warn" : "ok"} title="New devices not yet looked at" href="/fleet">
        {q.newDevices.names.length ? q.newDevices.names.map((d) => <span key={d.id} style={{ marginRight: 10 }}>{devLink(d.id, d.name)} <span className="mono">{d.ip}</span></span>) : "None."}
      </Q>
      <Q n={q.network.failing ? "✕" : q.network.unknown ? "?" : "✓"} mark={q.network.failing ? "bad" : q.network.unknown ? "none" : "ok"} title={`Network checks: ${q.network.of - q.network.failing - q.network.unknown} of ${q.network.of} passing`} href="/exposure">
        {q.network.factors.filter((f) => f.state !== "pass").map((f) => <div key={f.id}>{f.label}: {f.evidence}</div>)}
        {q.network.factors.every((f) => f.state === "pass") && "All passing."}
      </Q>
      <div className="two-col">
        <Gaps data={data} />
        <section className="card"><header><h2>Last 24 hours</h2><Link className="small" href="/activity">Activity</Link></header><Events events={data.events.slice(0, 12)} /></section>
      </div>
    </div>
  );
}

function Gaps({ data }: { data: Data }) {
  return (
    <section className="card">
      <header><h2>Could not check</h2><span className="muted small">{data.gapsTotal} item{data.gapsTotal === 1 ? "" : "s"}</span></header>
      {data.gaps.length === 0 ? <p className="small muted">Nothing outstanding.</p> : (
        <div className="list small">{data.gaps.map((g, i) => <div key={i}><span className="grow">{g.deviceId !== null && g.device ? <>{devLink(g.deviceId, g.device)} · </> : null}{g.check}<div className="muted">{g.evidence}</div></span></div>)}</div>
      )}
    </section>
  );
}

function Events({ events }: { events: Event[] }) {
  if (!events.length) return <p className="small muted">Nothing in the last 24 hours.</p>;
  return (
    <div className="list small">{events.map((e, i) => (
      <div key={i} className="ev"><span className="mono muted">{clock(e.at)}</span><span className={`dot ${e.tone === "bad" ? "bad" : e.tone === "warn" ? "warn" : ""}`} /><span className="grow">{e.link ? <Link href={e.link}>{e.text}</Link> : e.text}</span></div>
    ))}</div>
  );
}

function Ledger({ data }: { data: Data }) {
  const { questions: q, status } = data;
  return (
    <div className="stack">
      <div className="top"><div><h1>Overview</h1><p className="muted small">{when(data.at)} · Pi-hole {status.pihole ? (status.watch ? "watching" : "connected") : "not connected"}</p></div></div>
      <div className="two-col">
        <section className="card"><header><h2>Last 24 hours</h2><Link className="small" href="/activity">Full log</Link></header><Events events={data.events} /></section>
        <div className="stack">
          <section className="card">
            <header><h2>Now</h2></header>
            <div className="counts">
              <div><b className={q.contacts.count ? "crit" : ""}>{q.contacts.count}</b><span>indicator contacts not blocked</span></div>
              <div><b className={q.exploited.count ? "high" : ""}>{q.exploited.count}</b><span>exploited CVEs on devices</span></div>
              <div><b>{status.online}<span className="muted">/{status.devices}</span></b><span>devices online</span></div>
            </div>
            <div className="list small" style={{ marginTop: 10 }}>
              {q.network.factors.map((f) => <div key={f.id}><span className={`dot ${f.state === "fail" ? "bad" : f.state === "pass" ? "on" : ""}`} /><span className="grow">{f.label}</span><span className="muted">{f.state}</span></div>)}
              {q.newDevices.count > 0 && <div><span className="dot warn" /><span className="grow">{q.newDevices.count} new device{q.newDevices.count === 1 ? "" : "s"}</span><Link href="/fleet">Fleet</Link></div>}
            </div>
          </section>
          <Gaps data={data} />
        </div>
      </div>
    </div>
  );
}

export function Console({ data }: { data: Data }) {
  const [sel, setSel] = useState<number | null>(data.devices[0]?.id ?? null);
  const row = data.devices.find((d) => d.id === sel) ?? null;
  const { status } = data;
  return (
    <div className="stack">
      <div className="row small mono muted"><span>pihole {status.pihole ? "ok" : "off"}</span><span>watch {status.watch ? "on" : "off"}</span><span>{status.devices} dev · {status.online} up</span><span>{data.questions.contacts.count} contact · {data.questions.exploited.count} kev · {data.gapsTotal} gaps</span><span className="grow" /><span>{when(data.at)}</span></div>
      <div className="console">
        <section className="card" style={{ padding: 8 }}>
          <div className="table-wrap"><table className="dense">
            <thead><tr><th /><th>Device</th><th>Address</th><th>Hits 7d</th><th>KEV</th><th>Exposure</th><th>Agent</th><th>Seen</th></tr></thead>
            <tbody>{data.devices.map((d) => (
              <tr key={d.id} className={sel === d.id ? "sel" : undefined} onClick={() => setSel(d.id)} style={{ cursor: "pointer" }}>
                <td><span className={`dot ${d.notBlocked ? "bad" : d.kev || d.hits ? "warn" : d.online ? "on" : ""}`} /></td>
                <td><b>{d.name}</b>{d.isNew && <span className="badge b-high" style={{ marginLeft: 6 }}>new</span>}<div className="muted small">{d.kind ?? ""}</div></td>
                <td className="mono">{d.ip ?? "—"}</td>
                <td>{d.hits ? <><b className={d.notBlocked ? "crit" : ""}>{d.hits}</b> <span className="muted">/{d.notBlocked} open</span></> : "0"}</td>
                <td>{d.kev ? <b className="high">{d.kev}</b> : "0"}</td>
                <td>{d.exposure ? `${d.exposure.known}/${d.exposure.of}` : "—"}</td>
                <td className="muted">{d.agentAt ? ago(d.agentAt) : "n/a"}</td>
                <td className="muted">{ago(d.lastSeen)}</td>
              </tr>
            ))}</tbody>
          </table></div>
          {data.devices.length === 0 && <p className="small muted" style={{ padding: 8 }}>No devices. Connect Pi-hole or choose a network to sweep on Fleet.</p>}
        </section>
        <aside className="card stack" style={{ gap: 8 }}>
          {row ? (
            <>
              <div className="row"><h2>{row.name}</h2><span className="grow" /><Link className="small" href={`/fleet/devices/${row.id}`}>Device page</Link></div>
              <div className="kv"><span>address</span><span className="mono">{row.ip ?? "—"}</span><span>kind</span><span>{row.kind ?? "—"}</span><span>trust</span><span>{row.trusted ? "trusted" : "not trusted"}</span><span>seen</span><span>{when(row.lastSeen)}</span><span>agent</span><span>{row.agentAt ? when(row.agentAt) : "none"}</span></div>
              <h3>Indicator lookups · 7 days</h3>
              <div className="list small">{data.questions.contacts.top.filter((l) => l.deviceId === row.id).map((l) => <div key={`${l.clientIp}-${l.domain}-${l.via}`}><span className="mono grow">{l.indicator}</span><span className="badge b-crit">{l.lookups - l.blocked} not blocked</span></div>)}{!data.questions.contacts.top.some((l) => l.deviceId === row.id) && <div className="muted">{row.notBlocked ? `${row.notBlocked} not blocked (see device page)` : "none not blocked"}</div>}</div>
              <h3>Exploited CVEs</h3>
              <div className="list small">{data.questions.exploited.top.filter((e) => e.deviceId === row.id).map((e) => <div key={e.cveId}><span className="mono">{e.cveId}</span><span className="grow muted">{e.software}</span></div>)}{!data.questions.exploited.top.some((e) => e.deviceId === row.id) && <div className="muted">{row.kev ? `${row.kev} (see device page)` : "none"}</div>}</div>
              <h3>Could not check</h3>
              <div className="list small">{data.gaps.filter((g) => g.deviceId === row.id).map((g, i) => <div key={i}><span className="grow">{g.check}</span></div>)}{!data.gaps.some((g) => g.deviceId === row.id) && <div className="muted">nothing</div>}</div>
            </>
          ) : <p className="small muted">Select a device.</p>}
          <h3>Network</h3>
          <div className="list small">{data.questions.network.factors.map((f) => <div key={f.id}><span className={`dot ${f.state === "fail" ? "bad" : f.state === "pass" ? "on" : ""}`} /><span className="grow">{f.label}</span><span className="muted">{f.state}</span></div>)}</div>
        </aside>
      </div>
    </div>
  );
}
