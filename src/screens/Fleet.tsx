import { useCallback, useEffect, useMemo, useState } from "react";
import { api, lastLogLine, waitForJob, type Job } from "../api.ts";

type Device = {
  id: number; mac: string | null; ip: string | null; hostname: string | null; vendor: string | null; label: string | null; owner: string | null; kind: string | null; notes: string | null;
  tags: string[]; trusted: boolean; firstSeen: string; lastSeen: string; sources: Record<string, string>; addresses?: number; randomisedMac: boolean; online: boolean; isNew: boolean; name: string;
};
type DeviceDetail = Device & { addressHistory: { ip: string; firstSeen: string; lastSeen: string }[]; events: { id: number; at: string; kind: string; detail: Record<string, unknown> }[] };
type FleetEvent = { id: number; deviceId: number; at: string; kind: string; detail: Record<string, unknown>; device: string };
type Overview = {
  devices: Device[]; counts: { total: number; online: number; isNew: number; untrusted: number; randomised: number };
  targets: string[]; suggestions: { cidr: string; devices: number }[]; scanRanges: string[];
  lastSync: { at: string; pihole: number; arp: number; devices: number } | null;
  lastSweep: { at: string; networks: string[]; alive: number; withMac: number; newDevices: number } | null;
  events: FleetEvent[];
  vendors: { prefixes: number; at?: string; named?: number };
};

const sourceLabel: Record<string, string> = { pihole: "PH", arp: "ARP", sweep: "SWEEP" };
const sourceTitle: Record<string, string> = { pihole: "Pi-hole network table", arp: "neighbour (ARP) table", sweep: "network sweep" };
const eventText: Record<string, (d: Record<string, unknown>) => string> = {
  new: (d) => `New device at ${d.ip}`,
  inventoried: () => "Found in the first inventory",
  ip_changed: (d) => `Address ${d.from} → ${d.to}`,
  name_changed: (d) => `Name ${d.from} → ${d.to}`,
  merged: (d) => `Merged with what was seen at ${d.ip}`,
};
const kinds = ["phone", "tablet", "laptop", "desktop", "tv", "speaker", "camera", "iot", "storage", "router", "server", "console", "other"];

function ago(iso: string) {
  const s = Math.max(0, (Date.now() - Date.parse(iso)) / 1000);
  if (s < 90) return "now";
  if (s < 3600) return `${Math.round(s / 60)} min`;
  if (s < 86400 * 2) return `${Math.round(s / 3600)} h`;
  return `${Math.round(s / 86400)} days`;
}
const shortMac = (mac: string) => `${mac.slice(0, 8)}:…:${mac.slice(-2)}`;

export function FleetScreen() {
  const [overview, setOverview] = useState<Overview | null>(null);
  const [filter, setFilter] = useState<"all" | "new" | "online" | "offline" | "untrusted">("all");
  const [query, setQuery] = useState("");
  const [selected, setSelected] = useState<DeviceDetail | null>(null);
  const [targets, setTargets] = useState("");
  const [busy, setBusy] = useState("");
  const [message, setMessage] = useState<{ tone: "good" | "bad" | "warn"; text: string } | null>(null);

  const load = useCallback(async () => {
    const o = await api<Overview>("GET", "/api/fleet");
    setOverview(o);
    return o;
  }, []);
  useEffect(() => {
    load().then((o) => setTargets(o.targets.join("\n")), (e: Error) => setMessage({ tone: "bad", text: e.message }));
    const timer = setInterval(() => { void load().catch(() => {}); }, 60_000);
    return () => clearInterval(timer);
  }, [load]);

  const open = async (id: number) => setSelected((await api<{ device: DeviceDetail }>("GET", `/api/fleet/devices/${id}`)).device);
  const run = async (label: string, start: () => Promise<{ job: Job }>) => {
    setBusy(label);
    setMessage(null);
    try {
      const done = await waitForJob((await start()).job.id);
      setMessage({ tone: done.status === "succeeded" ? "good" : "bad", text: lastLogLine(done) || done.status });
      await load();
    } catch (error) {
      setMessage({ tone: "bad", text: error instanceof Error ? error.message : String(error) });
    } finally {
      setBusy("");
    }
  };
  const act = async (fn: () => Promise<unknown>, done: string) => {
    try {
      await fn();
      setMessage({ tone: "good", text: done });
      await load();
    } catch (error) {
      setMessage({ tone: "bad", text: error instanceof Error ? error.message : String(error) });
    }
  };
  const save = async (id: number, fields: Partial<Device>) => {
    try {
      setSelected((await api<{ device: DeviceDetail }>("PUT", `/api/fleet/devices/${id}`, fields)).device);
      await load();
    } catch (error) {
      setMessage({ tone: "bad", text: error instanceof Error ? error.message : String(error) });
    }
  };

  const rows = useMemo(() => {
    const q = query.trim().toLowerCase();
    return (overview?.devices ?? []).filter((d) => (filter === "all" || (filter === "new" && d.isNew) || (filter === "online" && d.online) || (filter === "offline" && !d.online) || (filter === "untrusted" && !d.trusted))
      && (!q || [d.name, d.ip, d.mac, d.hostname, d.vendor, d.owner, ...d.tags].some((v) => v?.toLowerCase().includes(q))));
  }, [overview, filter, query]);

  if (!overview) return <div className="stack"><h1>Fleet</h1>{message ? <div className="banner bad">{message.text}</div> : <p className="muted small">Loading…</p>}</div>;
  const { counts } = overview;

  return (
    <div className="stack">
      <div className="top">
        <div><h1>Fleet</h1><p className="muted small">Every device seen on your network, merged by MAC from Pi-hole’s network table, the neighbour table and sweeps of the networks you choose.</p></div>
        <div className="grow" />
        <button className="btn" type="button" disabled={Boolean(busy)} onClick={() => run("sync", () => api("POST", "/api/fleet/sync"))}>{busy === "sync" ? "Reading…" : "Read Pi-hole now"}</button>
        <button className="btn primary" type="button" disabled={Boolean(busy) || !overview.targets.length} title={overview.targets.length ? "" : "Choose networks to sweep below"} onClick={() => run("sweep", () => api("POST", "/api/fleet/sweep"))}>{busy === "sweep" ? "Sweeping…" : "Sweep now"}</button>
      </div>
      {message && <div className={`banner ${message.tone}`} role="status"><span className="small">{message.text}</span></div>}

      <div className="grid g4">
        <section className="card"><h3>Online</h3><div className="kpi">{counts.online}</div><p className="small muted">of {counts.total} known · seen in the last 15 minutes</p></section>
        <section className="card"><h3>New</h3><div className="kpi" style={{ color: counts.isNew ? "var(--high)" : undefined }}>{counts.isNew}</div><p className="small muted">not yet looked at; label or trust them to clear</p></section>
        <section className="card"><h3>Not trusted</h3><div className="kpi">{counts.untrusted}</div><p className="small muted">devices you have not marked as yours</p></section>
        <section className="card"><h3>Private MACs</h3><div className="kpi">{counts.randomised}</div><p className="small muted">randomised addresses: no vendor, may change</p></section>
      </div>

      {counts.total === 0 && (
        <div className="banner warn"><span className="small">No devices yet. Connect Pi-hole on the <a href="/pihole">Pi-hole Sentinel</a> screen and press “Read Pi-hole now”, or choose a network to sweep below.</span></div>
      )}

      <div className="two-col">
        <section className="card">
          <header>
            <div className="seg" role="group" aria-label="Filter devices">
              {([["all", "All"], ["new", `New${counts.isNew ? ` (${counts.isNew})` : ""}`], ["online", "Online"], ["offline", "Offline"], ["untrusted", "Not trusted"]] as const).map(([id, label]) => (
                <button key={id} type="button" aria-pressed={filter === id} onClick={() => setFilter(id)}>{label}</button>
              ))}
            </div>
            <input className="input" style={{ maxWidth: 240 }} placeholder="Search name, address, MAC, vendor…" value={query} onChange={(e) => setQuery(e.target.value)} aria-label="Search devices" />
          </header>
          <div className="table-wrap"><table>
            <thead><tr><th>Device</th><th>Address</th><th>Sources</th><th>First seen</th><th>Last seen</th></tr></thead>
            <tbody>{rows.map((d) => (
              <tr key={d.id} className={selected?.id === d.id ? "sel" : undefined}>
                <td style={{ whiteSpace: "nowrap" }}>
                  <span className={`dot ${d.online ? "on" : ""}`} aria-label={d.online ? "online" : "offline"} />{" "}
                  <button type="button" className="linkish" onClick={() => void open(d.id)}><b>{d.name}</b></button>
                  {d.isNew && <span className="badge b-high" style={{ marginLeft: 6 }}>new</span>}
                  {d.trusted && <span className="badge b-ok" style={{ marginLeft: 6 }}>trusted</span>}
                  <div className="muted small">{[d.vendor, d.kind, d.owner].filter(Boolean).join(" · ") || "unidentified"}{d.tags.length ? ` · ${d.tags.join(", ")}` : ""}</div>
                </td>
                <td className="mono small">{d.ip ?? "—"}<div className="muted">{d.mac ? (d.randomisedMac ? "private MAC" : shortMac(d.mac)) : "no MAC yet"}</div></td>
                <td><span className="src">{Object.keys(d.sources).map((s) => <i key={s} title={`${sourceTitle[s] ?? s}: ${new Date(d.sources[s]).toLocaleString()}`}>{sourceLabel[s] ?? s}</i>)}</span></td>
                <td className="small">{new Date(d.firstSeen).toLocaleDateString()}</td>
                <td className="small">{ago(d.lastSeen)}</td>
              </tr>
            ))}</tbody>
          </table></div>
          {rows.length === 0 && counts.total > 0 && <p className="small muted">No device matches.</p>}
        </section>

        <div className="stack sticky">
          {selected ? <DeviceCard key={selected.id} device={selected} onSave={(f) => save(selected.id, f)} onClose={() => setSelected(null)}
            onForget={() => act(async () => { await api("DELETE", `/api/fleet/devices/${selected.id}`); setSelected(null); }, `Forgot ${selected.name}; it reappears as new if seen again.`)} /> : (
            <section className="card stack">
              <h3>Recent changes</h3>
              {overview.events.length === 0 ? <p className="small muted">Nothing yet.</p> : (
                <div className="list small">{overview.events.map((e) => (
                  <div key={e.id}><span className="grow"><b>{e.device}</b> <span className="muted">{(eventText[e.kind] ?? (() => e.kind))(e.detail)}</span></span><span className="muted">{ago(e.at)}</span></div>
                ))}</div>
              )}
            </section>
          )}
          <section className="card stack">
            <h3>Networks to sweep</h3>
            <p className="small muted">Every 30 minutes TheySpy probes each address on these networks (a connection to a few common ports; nothing is logged in to). At most /22 each, inside {overview.scanRanges.join(", ")}.</p>
            <textarea className="input mono" rows={3} value={targets} onChange={(e) => setTargets(e.target.value)} placeholder="192.168.1.0/24" aria-label="Networks to sweep, one per line" />
            {overview.suggestions.filter((s) => !overview.targets.includes(s.cidr)).length > 0 && (
              <div className="row small">Suggested: {overview.suggestions.filter((s) => !overview.targets.includes(s.cidr)).map((s) => (
                <button key={s.cidr} type="button" className="btn small" onClick={() => setTargets([...targets.split(/\s+/).filter(Boolean), s.cidr].join("\n"))}>{s.cidr} · {s.devices}</button>
              ))}</div>
            )}
            <div><button className="btn" type="button" onClick={() => act(async () => { const r = await api<{ targets: string[] }>("PUT", "/api/fleet/targets", { targets: targets.split(/[\s,]+/).filter(Boolean) }); setTargets(r.targets.join("\n")); }, "Saved.")}>Save</button></div>
            <div className="list small">
              <div><span className="grow">Pi-hole read</span><span className="muted">{overview.lastSync ? `${ago(overview.lastSync.at)} · ${overview.lastSync.pihole} addresses` : "not yet"}</span></div>
              <div><span className="grow">Last sweep</span><span className="muted">{overview.lastSweep ? `${ago(overview.lastSweep.at)} · ${overview.lastSweep.alive} answered` : "not yet"}</span></div>
              <div><span className="grow">MAC vendor names (IEEE)</span><span className="muted">{overview.vendors.prefixes ? `${overview.vendors.prefixes.toLocaleString()} prefixes${overview.vendors.at ? ` · ${ago(overview.vendors.at)}` : ""}` : "not loaded"}</span>
                <button className="btn small" type="button" disabled={Boolean(busy)} onClick={() => run("vendors", () => api("POST", "/api/fleet/vendors"))}>{busy === "vendors" ? "Loading…" : "Update"}</button></div>
            </div>
          </section>
        </div>
      </div>
    </div>
  );
}

function DeviceCard({ device, onSave, onClose, onForget }: { device: DeviceDetail; onSave: (fields: Partial<Device>) => void; onClose: () => void; onForget: () => void }) {
  const [form, setForm] = useState({ label: device.label ?? "", owner: device.owner ?? "", kind: device.kind ?? "", tags: device.tags.join(", "), notes: device.notes ?? "" });
  return (
    <section className="card stack">
      <header><h2>{device.name}</h2><button className="btn small" type="button" onClick={onClose}>Close</button></header>
      <div className="list small">
        <div><span className="grow muted">Address</span><span className="mono">{device.ip ?? "—"}</span></div>
        <div><span className="grow muted">MAC</span><span className="mono">{device.mac ?? "not known yet"}{device.randomisedMac ? " (private)" : ""}</span></div>
        {device.hostname && <div><span className="grow muted">Name on the network</span><span className="mono">{device.hostname}</span></div>}
        <div><span className="grow muted">Vendor</span><span>{device.vendor ?? (device.randomisedMac ? "hidden by a private MAC" : "unknown")}</span></div>
        <div><span className="grow muted">First seen</span><span>{new Date(device.firstSeen).toLocaleString()}</span></div>
      </div>
      <div className="compact-fields">
      <div className="field"><label htmlFor="d-label">Name</label><input id="d-label" className="input" value={form.label} placeholder={device.hostname ?? ""} onChange={(e) => setForm({ ...form, label: e.target.value })} /></div>
      <div className="field"><label htmlFor="d-owner">Owner</label><input id="d-owner" className="input" value={form.owner} onChange={(e) => setForm({ ...form, owner: e.target.value })} /></div>
      <div className="field"><label htmlFor="d-kind">Kind</label>
        <select id="d-kind" className="input" value={form.kind} onChange={(e) => setForm({ ...form, kind: e.target.value })}><option value="">—</option>{kinds.map((k) => <option key={k} value={k}>{k}</option>)}</select></div>
      <div className="field"><label htmlFor="d-tags">Tags</label><input id="d-tags" className="input" value={form.tags} placeholder="iot, kids" onChange={(e) => setForm({ ...form, tags: e.target.value })} /></div>
      <div className="field"><label htmlFor="d-notes">Notes</label><textarea id="d-notes" className="input" rows={2} value={form.notes} onChange={(e) => setForm({ ...form, notes: e.target.value })} /></div>
      </div>
      <div className="row">
        <button className="btn primary" type="button" onClick={() => onSave({ label: form.label, owner: form.owner, kind: form.kind, notes: form.notes, tags: form.tags.split(",").map((t) => t.trim()).filter(Boolean) })}>Save</button>
        <button className="btn" type="button" onClick={() => onSave({ trusted: !device.trusted })}>{device.trusted ? "Stop trusting" : "Trust this device"}</button>
        {device.ip && <a className="btn" href={`/check?q=${encodeURIComponent(device.ip)}`}>Check it</a>}
        <button className="btn danger" type="button" onClick={onForget}>Forget</button>
      </div>
      {device.addressHistory.length > 1 && (
        <div><h3>Addresses</h3><div className="list small">{device.addressHistory.map((a) => <div key={a.ip}><span className="grow mono">{a.ip}</span><span className="muted">{ago(a.lastSeen)}</span></div>)}</div></div>
      )}
      <div><h3>History</h3><div className="list small">{device.events.map((e) => <div key={e.id}><span className="grow">{(eventText[e.kind] ?? (() => e.kind))(e.detail)}</span><span className="muted">{new Date(e.at).toLocaleString()}</span></div>)}</div></div>
    </section>
  );
}
