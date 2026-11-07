import { useEffect, useState } from "react";
import { api } from "../api.ts";
import { Link } from "../router.tsx";

// The ten checks TheySpy computes (three for the network, seven per device) as one list: each
// failing, not yet checked or passing, per device, with what would close it. On day one it is the
// order to set things up in; later it is the same list.

type State = "pass" | "partial" | "fail" | "unknown" | "na";
type Factor = { id: string; label: string; state: State; evidence: string; fix: string };
type Device = { id: number; name: string; factors: Factor[] };
type Data = { devices: Device[]; network: Factor[] };

const mark = { pass: "✓", partial: "!", fail: "✕", unknown: "?", na: "–" } as const;
const markBadge = { pass: "b-ok", partial: "b-med", fail: "b-crit", unknown: "b-info", na: "" } as const;

/** The steps a fresh install has left, from what the checks cannot see yet. */
function stepsFor(data: Data): { text: string; href: string }[] {
  const steps: { text: string; href: string }[] = [];
  const gateway = data.network.find((f) => f.id === "gateway");
  if (gateway && /not connected/i.test(gateway.evidence)) steps.push({ text: "Connect Pi-hole (or AdGuard Home, Technitium or OPNsense), so lookups can be read and blocked.", href: "/pihole" });
  else if (gateway?.state === "unknown") steps.push({ text: "Run the coverage check, so the network check can say which indicator domains Pi-hole blocks.", href: "/pihole" });
  if (!data.devices.length) steps.push({ text: "Read Pi-hole's network table, or choose a network to sweep, so there are devices to check.", href: "/fleet" });
  const watch = data.network.find((f) => f.id === "watch");
  if (watch && watch.state !== "pass" && !(gateway && /not connected/i.test(gateway.evidence))) steps.push({ text: "Turn the live watch on, so new indicator lookups are seen within 30 seconds.", href: "/pihole" });
  if (data.devices.length && !data.devices.some((d) => d.factors.some((f) => f.id === "scan" && f.state !== "na" && f.state !== "fail"))) steps.push({ text: "Add the agent to a computer, so its files and history are scanned.", href: "/evidence" });
  if (data.devices.length && data.devices.every((d) => d.factors.some((f) => f.id === "blocker" && f.state === "unknown"))) steps.push({ text: "Open This device on each phone and computer once, so ad blocking, GPC and the DNS path are known.", href: "/this-device" });
  const egress = data.network.find((f) => f.id === "egress");
  if (egress?.state === "unknown") steps.push({ text: "Press Check my connection on Ad exposure once, so the Starlink check is known.", href: "/exposure" });
  return steps;
}

export function ChecksScreen() {
  const [data, setData] = useState<Data | null>(null);
  const [error, setError] = useState("");
  useEffect(() => { api<Data>("GET", "/api/exposure").then(setData, (e: Error) => setError(e.message)); }, []);
  if (error) return <div className="stack"><h1>Checks</h1><div className="banner bad">{error}</div></div>;
  if (!data) return <div className="stack"><h1>Checks</h1><p className="muted small">Loading…</p></div>;

  const ids = [...new Set(data.devices.flatMap((d) => d.factors.map((f) => f.id)))];
  const rows = ids.map((id) => {
    const per = data.devices.map((d) => ({ device: d, f: d.factors.find((x) => x.id === id) })).filter((x): x is { device: Device; f: Factor } => Boolean(x.f));
    const count = (state: State) => per.filter((x) => x.f.state === state).length;
    const first = per[0]?.f;
    const state: State = count("fail") ? "fail" : count("partial") ? "partial" : count("unknown") ? "unknown" : count("pass") ? "pass" : "na";
    return { id, label: first?.label ?? id, fix: first?.fix ?? "", state, counts: { pass: count("pass"), partial: count("partial"), fail: count("fail"), unknown: count("unknown"), na: count("na") }, failing: per.filter((x) => x.f.state === "fail" || x.f.state === "partial").map((x) => x.device), unknown: per.filter((x) => x.f.state === "unknown").map((x) => x.device) };
  });
  const all = [...data.network, ...rows];
  const passing = all.filter((r) => r.state === "pass").length;
  const failing = all.filter((r) => r.state === "fail" || r.state === "partial").length;
  const unknown = all.filter((r) => r.state === "unknown").length;
  const steps = stepsFor(data);
  const names = (list: Device[]) => list.slice(0, 6).map((d, i) => <span key={d.id}>{i ? ", " : ""}<Link href={`/fleet/devices/${d.id}`}>{d.name}</Link></span>);

  return (
    <div className="stack">
      <div className="top">
        <div><h1>Checks</h1><p className="muted small">{data.network.length + rows.length} checks: {passing} passing everywhere, {failing} failing somewhere, {unknown} not yet checked. A check that could not run is never shown as clean.</p></div>
      </div>
      {steps.length > 0 && (
        <section className="card">
          <header><h2>To set up</h2><span className="muted small">{steps.length} step{steps.length === 1 ? "" : "s"} left</span></header>
          <ol className="small" style={{ margin: 0, paddingLeft: 20 }}>{steps.map((s) => <li key={s.href + s.text} style={{ marginBottom: 6 }}>{s.text} <Link href={s.href}>Open</Link></li>)}</ol>
        </section>
      )}
      <section className="card">
        <header><h2>Network</h2></header>
        <div className="list small">{data.network.map((f) => (
          <div key={f.id} style={{ alignItems: "flex-start" }}><span className={`badge ${markBadge[f.state]}`}>{mark[f.state]}</span><span className="grow"><b>{f.label}</b><br /><span className="muted">{f.evidence}</span>{f.state !== "pass" && f.state !== "na" && <><br /><span>Fix: {f.fix}</span></>}</span></div>
        ))}</div>
      </section>
      <section className="card">
        <header><h2>Devices</h2><span className="muted small">{data.devices.length} device{data.devices.length === 1 ? "" : "s"} · <Link href="/exposure">per device</Link></span></header>
        {rows.length === 0 ? <p className="small muted">No devices yet.</p> : (
          <div className="list small">{rows.map((r) => (
            <div key={r.id} style={{ alignItems: "flex-start" }}>
              <span className={`badge ${markBadge[r.state]}`}>{mark[r.state]}</span>
              <span className="grow">
                <b>{r.label}</b> <span className="muted">· {r.counts.pass} pass{r.counts.partial ? ` · ${r.counts.partial} partial` : ""}{r.counts.fail ? ` · ${r.counts.fail} fail` : ""}{r.counts.unknown ? ` · ${r.counts.unknown} not checked` : ""}{r.counts.na ? ` · ${r.counts.na} n/a` : ""}</span>
                {r.failing.length > 0 && <><br /><span>Failing: {names(r.failing)}{r.failing.length > 6 ? ` and ${r.failing.length - 6} more` : ""}</span></>}
                {r.unknown.length > 0 && <><br /><span className="muted">Not checked: {names(r.unknown)}{r.unknown.length > 6 ? ` and ${r.unknown.length - 6} more` : ""}</span></>}
                {r.state !== "pass" && r.state !== "na" && <><br /><span>Fix: {r.fix}</span></>}
              </span>
            </div>
          ))}</div>
        )}
      </section>
    </div>
  );
}
