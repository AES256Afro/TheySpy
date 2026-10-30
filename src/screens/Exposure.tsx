import { useCallback, useEffect, useState } from "react";
import { api } from "../api.ts";

type Factor = { id: string; label: string; state: "pass" | "partial" | "fail" | "unknown" | "na"; evidence: string; fix: string };
type Scored = { score: number | null; tone: "good" | "warn" | "bad" | "unknown"; known: number; of: number };
type Device = Scored & { id: number; name: string; ip: string | null; kind: string | null; factors: Factor[] };
type Data = { devices: Device[]; network: Factor[]; networkScore: Scored; average: number | null };

const mark = { pass: "✓", partial: "!", fail: "✕", unknown: "?", na: "–" } as const;
const markBadge = { pass: "b-ok", partial: "b-med", fail: "b-crit", unknown: "b-info", na: "" } as const;
const toneBadge = { good: "b-ok", warn: "b-med", bad: "b-crit", unknown: "b-info" } as const;
const columns = ["dns", "blocker", "adid", "gpc", "patched", "clean", "scan"];
const kitList = [
  ["apple", "Apple profile", "Turns off personalised ads and tracking requests on iPhone, iPad and Mac.", ".mobileconfig"],
  ["android", "Android steps", "Delete the advertising ID; let Pi-hole answer DNS at home.", ".txt"],
  ["windows", "Windows policy", "Advertising ID off, Edge tracking prevention strict, GPC in Firefox.", ".reg"],
  ["browsers", "Browser settings", "GPC, a blocker, and the browser’s own DNS off, for each browser.", ".txt"],
] as const;

export function ExposureScreen() {
  const [data, setData] = useState<Data | null>(null);
  const [open, setOpen] = useState<number | null>(null);
  const [message, setMessage] = useState<{ tone: "good" | "bad"; text: string } | null>(null);
  const load = useCallback(async () => setData(await api<Data>("GET", "/api/exposure")), []);
  useEffect(() => { load().catch((e: Error) => setMessage({ tone: "bad", text: e.message })); }, [load]);

  if (!data) return <div className="stack"><h1>Ad exposure</h1>{message ? <div className="banner bad">{message.text}</div> : <p className="muted small">Loading…</p>}</div>;
  const device = data.devices.find((d) => d.id === open) ?? null;
  return (
    <div className="stack">
      <div className="top"><div><h1>Ad exposure</h1><p className="muted small">“There is currently no consistently safe way to expose your users and networks to targeted ads.” — Citizen Lab. Each line below is a live check with what it was decided on and how to fix it.</p></div></div>
      {message && <div className={`banner ${message.tone}`} role="status"><span className="small">{message.text}</span></div>}

      <div className="grid g3">
        <section className="card"><h3>Network</h3><div className="kpi">{data.networkScore.score ?? "—"}</div><span className={`badge ${toneBadge[data.networkScore.tone]}`}>{data.networkScore.known} of {data.networkScore.of} checks known</span></section>
        <section className="card"><h3>Devices (average)</h3><div className="kpi">{data.average ?? "—"}</div><p className="small muted">{data.devices.filter((d) => d.tone === "bad").length} red · {data.devices.filter((d) => d.tone === "warn").length} amber · {data.devices.filter((d) => d.tone === "good").length} green · {data.devices.filter((d) => d.tone === "unknown").length} not enough known yet</p></section>
        <section className="card stack"><h3>Your connection</h3>
          <p className="small muted">Is this network’s public address Starlink’s (which ad bidders can target)? Asks Cloudflare for the address and compares it with SpaceX’s published list; the address is not kept.</p>
          <div><button className="btn" type="button" onClick={() => void api("POST", "/api/exposure/egress").then(load, (e: Error) => setMessage({ tone: "bad", text: e.message }))}>Check my connection</button></div>
        </section>
      </div>

      <section className="card stack">
        <header><h2>Network</h2></header>
        <div className="list small">{data.network.map((f) => <FactorRow key={f.id} f={f} />)}</div>
      </section>

      <div className="two-col">
        <section className="card">
          <header><h2>Per device</h2><span className="muted small">✓ pass · ! partial · ✕ fail · ? not known yet · – does not apply</span></header>
          <div className="table-wrap"><table>
            <thead><tr><th>Device</th>{["Pi-hole DNS", "Blocker", "Ad ID off", "GPC", "Patched", "No contact", "Scanned"].map((h) => <th key={h}>{h}</th>)}<th>Score</th></tr></thead>
            <tbody>{data.devices.map((d) => (
              <tr key={d.id} className={open === d.id ? "sel" : undefined}>
                <td><button type="button" className="linkish" onClick={() => setOpen(d.id)}><b>{d.name}</b></button><div className="muted small">{d.kind ?? ""}</div></td>
                {columns.map((c) => { const f = d.factors.find((x) => x.id === c); return <td key={c} title={f ? `${f.label}: ${f.evidence}` : ""}>{f && f.state !== "na" ? <span className={`badge ${markBadge[f.state]}`}>{mark[f.state]}</span> : <span className="muted">–</span>}</td>; })}
                <td>{d.score === null ? <span className="muted">—</span> : <span className={`badge ${toneBadge[d.tone]}`} title={d.tone === "unknown" ? `Only ${d.known} of ${d.of} checks known yet` : `${d.known} of ${d.of} checks known`}>{d.score}{d.tone === "unknown" ? "?" : ""}</span>}</td>
              </tr>
            ))}</tbody>
          </table></div>
        </section>
        <div className="stack sticky">
          {device ? (
            <section className="card stack">
              <header><h2>{device.name}</h2><button className="btn small" type="button" onClick={() => setOpen(null)}>Close</button></header>
              <div className="list small">{device.factors.map((f) => <FactorRow key={f.id} f={f} />)}</div>
              <p className="small muted">Open TheySpy’s <a href="/this-device">This device</a> page on it after a change to re-check; phone details live in the <a href="/evidence">Evidence locker</a>.</p>
            </section>
          ) : (
            <section className="card stack"><h3>Hardening kits</h3>
              <div className="list small">{kitList.map(([id, name, what, ext]) => (
                <div key={id} style={{ alignItems: "flex-start" }}><span className="grow"><b>{name}</b><br /><span className="muted">{what}</span></span><a className="btn small" href={`/api/exposure/kits/${id}`}>{ext}</a></div>
              ))}</div>
              <p className="small muted">Pi-hole side: subscribe to TheySpy’s Recommended list (Blocklist library) and pick a baseline per device (Baselines). Click a device for its own checklist.</p>
            </section>
          )}
        </div>
      </div>
    </div>
  );
}

function FactorRow({ f }: { f: Factor }) {
  return (
    <div style={{ alignItems: "flex-start" }}>
      <span className={`badge ${markBadge[f.state]}`}>{mark[f.state]}</span>
      <span className="grow"><b>{f.label}</b><br /><span className="muted">{f.evidence}</span>{f.state !== "pass" && f.state !== "na" && <><br /><span>Fix: {f.fix}</span></>}</span>
    </div>
  );
}
