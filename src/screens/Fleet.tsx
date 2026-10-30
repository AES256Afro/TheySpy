import { useCallback, useEffect, useMemo, useState } from "react";
import { api, lastLogLine, waitForJob, type Job } from "../api.ts";

type Device = {
  id: number; mac: string | null; ip: string | null; hostname: string | null; vendor: string | null; label: string | null; owner: string | null; kind: string | null; notes: string | null;
  tags: string[]; trusted: boolean; firstSeen: string; lastSeen: string; sources: Record<string, string>; addresses?: number; randomisedMac: boolean; online: boolean; isNew: boolean; name: string;
  nameFrom: string; names: { pihole?: string; piholeClient?: string; netalertx?: string; router?: string; tailscale?: string; checkedAt?: string };
  network: { kind: string; label: string; detail: string } | null; guess: { kind: string | null; label: string; from: string } | null; inPihole: boolean;
  homeIp: string | null; tailscaleIp: string | null;
};
type MergeSuggestion = { into: { id: number; name: string; ip: string | null }; from: { id: number; name: string; ip: string | null }; why: string };
type DeviceDetail = Device & { addressHistory: { ip: string; firstSeen: string; lastSeen: string }[]; events: { id: number; at: string; kind: string; detail: Record<string, unknown> }[] };
type FleetEvent = { id: number; deviceId: number; at: string; kind: string; detail: Record<string, unknown>; device: string };
type Overview = {
  devices: Device[]; counts: { total: number; online: number; isNew: number; untrusted: number; randomised: number; piholeUntrusted: number };
  targets: string[]; suggestions: { cidr: string; devices: number }[]; mergeSuggestions: MergeSuggestion[]; scanRanges: string[];
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
// Where a device lives: on your home network (it has an address there), or reached only over Tailscale.
const groups = [
  { id: "home", title: "Home network", hint: "Connected to your router; its Tailscale address, if any, is shown with it" },
  { id: "tailscale", title: "Tailscale only", hint: "In your tailnet but not seen at home: away from home, or a server elsewhere" },
  { id: "unknown", title: "Not placed yet", hint: "No home or Tailscale address known" },
] as const;
const groupOf = (d: Device) => (d.homeIp && d.network?.kind !== "docker" ? "home" : d.tailscaleIp ? "tailscale" : "unknown");
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
  const [filter, setFilter] = useState<"all" | "new" | "online" | "offline" | "untrusted" | "pihole">("all");
  const [query, setQuery] = useState("");
  const [showContainers, setShowContainers] = useState(false);
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
    return (overview?.devices ?? []).filter((d) => (showContainers || d.network?.kind !== "docker") && (filter === "all" || (filter === "new" && d.isNew) || (filter === "online" && d.online) || (filter === "offline" && !d.online) || (filter === "untrusted" && !d.trusted) || (filter === "pihole" && d.inPihole))
      && (!q || [d.name, d.ip, d.mac, d.hostname, d.vendor, d.owner, d.names.pihole, d.names.router, d.names.tailscale, d.tailscaleIp, d.network?.label, d.guess?.label, ...d.tags].some((v) => v?.toLowerCase().includes(q))));
  }, [overview, filter, query, showContainers]);
  const containers = (overview?.devices ?? []).filter((d) => d.network?.kind === "docker").length;

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

      {counts.piholeUntrusted > 0 && (
        <div className="banner">
          <span className="small grow">{counts.piholeUntrusted} device{counts.piholeUntrusted === 1 ? " is" : "s are"} already listed as clients in your Pi-hole but not trusted here. Devices you set up in Pi-hole are usually yours.</span>
          <button className="btn small" type="button" onClick={() => setFilter("pihole")}>Show them</button>
          <button className="btn small primary" type="button" onClick={() => act(async () => { const r = await api<{ trusted: number }>("POST", "/api/fleet/trust-pihole-clients"); return r; }, `Trusted ${counts.piholeUntrusted} device${counts.piholeUntrusted === 1 ? "" : "s"} listed in Pi-hole.`)}>Trust all {counts.piholeUntrusted}</button>
        </div>
      )}
      {overview.mergeSuggestions.length > 0 && (
        <section className="card stack">
          <h3>Same device?</h3>
          <p className="small muted">These look like one device seen twice, for example at home and over Tailscale. Merging keeps one record with both addresses; TheySpy merges by itself only when the names prove it.</p>
          <div className="list small">{overview.mergeSuggestions.map((m) => (
            <div key={`${m.from.id}-${m.into.id}`}>
              <span className="grow"><b>{m.from.name}</b> <span className="mono muted">{m.from.ip}</span> and <b>{m.into.name}</b> <span className="mono muted">{m.into.ip}</span></span>
              <button className="btn small primary" type="button" onClick={() => act(() => api("POST", `/api/fleet/devices/${m.from.id}/merge`, { into: m.into.id }), `Merged ${m.from.name} into ${m.into.name}.`)}>Merge</button>
              <button className="btn small" type="button" onClick={() => act(() => api("POST", "/api/fleet/not-same", { a: m.from.id, b: m.into.id }), "Kept apart; not suggested again.")}>Not the same</button>
            </div>
          ))}</div>
        </section>
      )}
      {counts.total === 0 && (
        <div className="banner warn"><span className="small">No devices yet. Connect Pi-hole on the <a href="/pihole">Pi-hole Sentinel</a> screen and press “Read Pi-hole now”, or choose a network to sweep below.</span></div>
      )}

      <div className="two-col">
        <section className="card">
          <header>
            <div className="seg" role="group" aria-label="Filter devices">
              {([["all", "All"], ["new", `New${counts.isNew ? ` (${counts.isNew})` : ""}`], ["online", "Online"], ["offline", "Offline"], ["untrusted", "Not trusted"], ["pihole", "In Pi-hole"]] as const).map(([id, label]) => (
                <button key={id} type="button" aria-pressed={filter === id} onClick={() => setFilter(id)}>{label}</button>
              ))}
            </div>
            {containers > 0 && <label className="small row" style={{ gap: 4 }} title="Containers on Docker networks on the Pi-hole host: apps asking Pi-hole, not separate devices"><input type="checkbox" checked={showContainers} onChange={(e) => setShowContainers(e.target.checked)} />Show {containers} Docker containers</label>}
            <input className="input" style={{ maxWidth: 240 }} placeholder="Search name, address, MAC, vendor…" value={query} onChange={(e) => setQuery(e.target.value)} aria-label="Search devices" />
          </header>
          <div className="table-wrap"><table>
            <thead><tr><th>Device</th><th>Address</th><th>Sources</th><th>First seen</th><th>Last seen</th></tr></thead>
            <tbody>{groups.map((g) => ({ g, items: rows.filter((d) => groupOf(d) === g.id) })).filter(({ items }) => items.length).map(({ g, items }) => [
              <tr key={`g-${g.id}`} className="group"><th colSpan={5} title={g.hint}>{g.title} <span className="muted small">· {items.length}</span></th></tr>,
              ...items.map((d) => (
              <tr key={d.id} className={selected?.id === d.id ? "sel" : undefined}>
                <td style={{ whiteSpace: "nowrap" }}>
                  <span className={`dot ${d.online ? "on" : ""}`} aria-label={d.online ? "online" : "offline"} />{" "}
                  <button type="button" className="linkish" onClick={() => void open(d.id)}><b>{d.name}</b></button>
                  {d.isNew && <span className="badge b-high" style={{ marginLeft: 6 }}>new</span>}
                  {d.trusted && <span className="badge b-ok" style={{ marginLeft: 6 }}>trusted</span>}
                  {d.inPihole && <span className="badge b-info" style={{ marginLeft: 6 }} title="You set this device up as a client in Pi-hole (Group management → Clients)">in Pi-hole</span>}
                  <div className="muted small" title={`Name from ${d.nameFrom}`}>{[d.kind ?? d.guess?.label, d.vendor, d.owner].filter(Boolean).join(" · ") || "not identified yet"}{d.tags.length ? ` · ${d.tags.join(", ")}` : ""}</div>
                  {d.network && <div className="small" title={d.network.detail}><span className={`badge ${networkBadge[d.network.kind] ?? "b-info"}`}>{d.network.label}</span></div>}
                </td>
                <td className="mono small">{d.homeIp ?? d.tailscaleIp ?? d.ip ?? "—"}{d.homeIp && d.tailscaleIp && <div title="Its Tailscale address">{d.tailscaleIp} <span className="muted">tailscale</span></div>}<div className="muted">{d.mac ? (d.randomisedMac ? "private MAC" : shortMac(d.mac)) : "no MAC yet"}</div></td>
                <td><span className="src">{Object.keys(d.sources).map((s) => <i key={s} title={`${sourceTitle[s] ?? s}: ${new Date(d.sources[s]).toLocaleString()}`}>{sourceLabel[s] ?? s}</i>)}</span></td>
                <td className="small">{new Date(d.firstSeen).toLocaleDateString()}</td>
                <td className="small">{ago(d.lastSeen)}</td>
              </tr>
            ))])}</tbody>
          </table></div>
          {rows.length === 0 && counts.total > 0 && <p className="small muted">No device matches.</p>}
        </section>

        <div className="stack sticky">
          {selected ? <DeviceCard key={selected.id} device={selected} others={(overview.devices).filter((d) => d.id !== selected.id && d.network?.kind !== "docker")}
            onMerge={(into) => act(async () => { setSelected((await api<{ device: DeviceDetail }>("POST", `/api/fleet/devices/${selected.id}/merge`, { into })).device); }, "Merged; one device with both addresses.")} onSave={(f) => save(selected.id, f)} onClose={() => setSelected(null)}
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
          <NetAlertXCard onChanged={() => void load()} />
          <ProtecCard devices={overview.devices} onChanged={() => void load()} />
        </div>
      </div>
    </div>
  );
}

type NetAlertXConfig = { configured: boolean; url: string | null; hasToken: boolean; write: boolean; lastSync: { at: string; devices: number; added: number; named: number; filled: number; toFill: number } | null };
type Fill = { mac: string; device: string; column: string; from: string; to: string };
const columnLabel: Record<string, string> = { devName: "name", devOwner: "owner", devType: "type" };

/** NetAlertX both ways: its devices and names come in; TheySpy fills only empty fields there. */
function NetAlertXCard({ onChanged }: { onChanged: () => void }) {
  const [config, setConfig] = useState<NetAlertXConfig | null>(null);
  const [url, setUrl] = useState("");
  const [token, setToken] = useState("");
  const [fills, setFills] = useState<Fill[] | null>(null);
  const [note, setNote] = useState<{ tone: "good" | "bad"; text: string } | null>(null);
  const load = useCallback(async () => { const c = await api<NetAlertXConfig>("GET", "/api/fleet/netalertx"); setConfig(c); setUrl((u) => u || c.url || ""); }, []);
  useEffect(() => { void load().catch(() => {}); }, [load]);
  const step = async (fn: () => Promise<string>) => {
    setNote(null);
    try { setNote({ tone: "good", text: await fn() }); await load(); onChanged(); } catch (e) { setNote({ tone: "bad", text: e instanceof Error ? e.message : String(e) }); }
  };
  if (!config) return null;
  return (
    <section className="card stack">
      <h3>NetAlertX</h3>
      <p className="small muted">Its devices join the Fleet, with the names, owners and types you gave them there. TheySpy can fill the same fields in NetAlertX where they are empty, never ones you filled, and only after you allow it.</p>
      <div className="compact-fields">
      <div className="field"><label htmlFor="nax-url">API address</label><input id="nax-url" className="input" placeholder="http://192.168.1.5:20212" value={url} onChange={(e) => setUrl(e.target.value)} /><span className="hint">NetAlertX&apos;s API port (GRAPHQL_PORT), 20212 by default.</span></div>
      <div className="field"><label htmlFor="nax-token">API token</label><input id="nax-token" className="input" type="password" autoComplete="off" placeholder={config.hasToken ? "Saved (leave empty to keep)" : "Settings → API → API_TOKEN"} value={token} onChange={(e) => setToken(e.target.value)} /></div>
      </div>
      <div className="row">
        <button className="btn" type="button" onClick={() => step(async () => { await api("PUT", "/api/fleet/netalertx", { url, ...(token ? { token } : {}) }); setToken(""); const t = await api<{ devices: number }>("POST", "/api/fleet/netalertx/test"); return `Connected: NetAlertX lists ${t.devices} devices.`; })}>Save and test</button>
        {config.configured && <button className="btn" type="button" onClick={() => step(async () => { const r = await api<{ devices: number; added: number; named: number; filled: number }>("POST", "/api/fleet/netalertx/sync"); return `Synced ${r.devices} devices: ${r.added} new here, ${r.named} named by NetAlertX, ${r.filled} with owner or type filled.`; })}>Sync now</button>}
        {config.configured && <button className="btn" type="button" onClick={() => step(async () => { const r = await api<{ changes: Fill[] }>("GET", "/api/fleet/netalertx/preview"); setFills(r.changes); return r.changes.length ? `${r.changes.length} empty NetAlertX field(s) TheySpy could fill: see below.` : "Nothing to fill in NetAlertX."; })}>Preview filling NetAlertX</button>}
      </div>
      {config.lastSync && <span className="small muted">Last sync {ago(config.lastSync.at)}: {config.lastSync.devices} devices · runs every 30 minutes</span>}
      {fills && fills.length > 0 && (
        <>
          <div className="list small">{fills.map((f) => <div key={`${f.mac}-${f.column}`}><span className="grow">{f.device}: {columnLabel[f.column] ?? f.column} <span className="muted">{f.from || "(empty)"}</span> → <b>{f.to}</b></span></div>)}</div>
          {config.write
            ? <div><button className="btn primary" type="button" onClick={() => step(async () => { const r = await api<{ filled: number }>("POST", "/api/fleet/netalertx/push"); setFills(null); return `Filled ${r.filled} field(s) in NetAlertX.`; })}>Fill these in NetAlertX</button></div>
            : <div><button className="btn" type="button" onClick={() => step(async () => { await api("PUT", "/api/fleet/netalertx", { write: true }); return "TheySpy may now fill empty fields in NetAlertX. Press Fill when you are ready."; })}>Allow TheySpy to fill empty fields in NetAlertX</button></div>}
        </>
      )}
      {config.write && <div><button className="btn small" type="button" onClick={() => step(async () => { await api("PUT", "/api/fleet/netalertx", { write: false }); setFills(null); return "TheySpy will not change NetAlertX."; })}>Stop TheySpy changing NetAlertX</button></div>}
      {note && <div className={`banner ${note.tone}`} role="status"><span className="small">{note.text}</span></div>}
    </section>
  );
}

type ProtecState = { configured: boolean; url: string | null; hasToken: boolean; lastError: { at: string; error: string } | null; lastSync: { at: string; machines: number; matched: number; packages: number; unmatched: { id: string; hostname: string; os: string; packages: number }[] } | null };

/** Protec's package inventory, read with a viewer credential, for CVE matching on each machine. */
function ProtecCard({ devices, onChanged }: { devices: Device[]; onChanged: () => void }) {
  const [state, setState] = useState<ProtecState | null>(null);
  const [url, setUrl] = useState("");
  const [token, setToken] = useState("");
  const [note, setNote] = useState<{ tone: "good" | "bad"; text: string } | null>(null);
  const load = useCallback(async () => { const s = await api<ProtecState>("GET", "/api/protec"); setState(s); setUrl((u) => u || s.url || ""); }, []);
  useEffect(() => { void load().catch(() => {}); }, [load]);
  const step = async (fn: () => Promise<string>) => {
    setNote(null);
    try { setNote({ tone: "good", text: await fn() }); await load(); onChanged(); } catch (e) { setNote({ tone: "bad", text: e instanceof Error ? e.message : String(e) }); }
  };
  const sync = async () => { const r = await api<{ machines: number; matched: number; packages: number; unmatched: unknown[] }>("POST", "/api/protec/sync"); return `Read ${r.machines} machine(s): ${r.matched} matched to Fleet devices, ${r.packages} package(s) to check for CVEs${r.unmatched.length ? `, ${r.unmatched.length} to link below` : ""}.`; };
  if (!state) return null;
  return (
    <section className="card stack">
      <h3>Protec</h3>
      <p className="small muted">Each enrolled machine&apos;s installed packages (dpkg, Homebrew) are checked for CVEs on its Fleet device. Debian and Ubuntu fix bugs without changing the version, so a CVE matched from a Linux package may already be patched; your updates are what fix it.</p>
      <div className="compact-fields">
        <div className="field"><label htmlFor="protec-url">Address</label><input id="protec-url" className="input" placeholder="https://protec.example.ts.net:8765" value={url} onChange={(e) => setUrl(e.target.value)} /></div>
        <div className="field"><label htmlFor="protec-token">Viewer credential</label><input id="protec-token" className="input" type="password" autoComplete="off" placeholder={state.hasToken ? "Saved (leave empty to keep)" : "Protec → Access → viewer"} value={token} onChange={(e) => setToken(e.target.value)} /><span className="hint">A viewer credential reads only. Protec&apos;s last at most 720 hours: issue a new one when it runs out.</span></div>
      </div>
      <div className="row">
        <button className="btn" type="button" onClick={() => step(async () => { await api("PUT", "/api/protec", { url, ...(token ? { token } : {}) }); setToken(""); return sync(); })}>Save and read</button>
        {state.configured && <button className="btn" type="button" onClick={() => step(sync)}>Read now</button>}
      </div>
      {state.lastError && <div className="banner bad"><span className="small">The last hourly read failed {ago(state.lastError.at)}: {state.lastError.error}</span></div>}
      {state.lastSync && <span className="small muted">Read {ago(state.lastSync.at)}: {state.lastSync.matched} of {state.lastSync.machines} machines matched · every hour</span>}
      {(state.lastSync?.unmatched ?? []).length > 0 && (
        <div className="list small">{state.lastSync!.unmatched.map((m) => (
          <div key={m.id}><span className="grow"><b>{m.hostname || m.id}</b> <span className="muted">{m.os} · {m.packages} package(s)</span></span>
            <select className="input" aria-label={`Fleet device for ${m.hostname}`} defaultValue="" onChange={(e) => e.target.value && step(async () => { await api("POST", "/api/protec/link", { machineId: m.id, deviceId: Number(e.target.value) }); return `Linked; ${await sync()}`; })}>
              <option value="">Link to…</option>{devices.filter((d) => d.network?.kind !== "docker").map((d) => <option key={d.id} value={d.id}>{d.name}</option>)}
            </select></div>
        ))}</div>
      )}
      {note && <div className={`banner ${note.tone}`} role="status"><span className="small">{note.text}</span></div>}
    </section>
  );
}

function DeviceCard({ device, others, onMerge, onSave, onClose, onForget }: { device: DeviceDetail; others: Device[]; onMerge: (into: number) => void; onSave: (fields: Partial<Device>) => void; onClose: () => void; onForget: () => void }) {
  const [form, setForm] = useState({ label: device.label ?? "", owner: device.owner ?? "", kind: device.kind ?? "", tags: device.tags.join(", "), notes: device.notes ?? "" });
  return (
    <section className="card stack">
      <header><h2>{device.name}</h2><button className="btn small" type="button" onClick={onClose}>Close</button></header>
      <p className="small muted">Called “{device.name}” from {device.nameFrom}.{device.guess ? ` Probably: ${device.guess.label} (from ${device.guess.from}).` : ""}</p>
      {device.network && <div className="banner"><span className="small"><b>{device.network.label}.</b> {device.network.detail}</span></div>}
      <div className="list small">
        {device.inPihole && <div><span className="grow muted">In your Pi-hole</span><span>listed as a client{device.names.pihole ? ` named “${device.names.pihole}”` : ""}</span>{!device.trusted && <button className="btn small primary" type="button" onClick={() => onSave({ trusted: true })}>Trust</button>}</div>}
        {device.names.router && <div><span className="grow muted">Name on your router</span><span className="mono">{device.names.router}</span></div>}
        {device.names.tailscale && <div><span className="grow muted">Tailscale name</span><span className="mono">{device.names.tailscale}</span></div>}
        <div><span className="grow muted">Home address</span><span className="mono">{device.homeIp ?? "not seen at home"}</span></div>
        {device.tailscaleIp && <div><span className="grow muted">Tailscale address</span><span className="mono">{device.tailscaleIp}</span></div>}
        <div><span className="grow muted">MAC</span><span className="mono">{device.mac ?? "not known yet"}{device.randomisedMac ? " (private)" : ""}</span></div>
        {device.hostname && <div><span className="grow muted">Name on the network</span><span className="mono">{device.hostname}</span></div>}
        <div><span className="grow muted">Vendor</span><span>{device.vendor ?? (device.randomisedMac ? "hidden by a private MAC" : "unknown")}</span></div>
        {device.randomisedMac && <div><span className="grow muted small">Phones, tablets and laptops use a private (random) MAC per Wi-Fi network, so the maker cannot be read from it.</span></div>}
        <div><span className="grow muted">First seen</span><span>{new Date(device.firstSeen).toLocaleString()}</span></div>
      </div>
      <Activity deviceId={device.id} />
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
      <div className="row small">
        <label htmlFor="d-merge" className="muted">Same device as</label>
        <select id="d-merge" className="input" style={{ maxWidth: 260 }} value="" onChange={(e) => { if (e.target.value) onMerge(Number(e.target.value)); }}>
          <option value="">Merge into…</option>{others.map((d) => <option key={d.id} value={d.id}>{d.name} · {d.homeIp ?? d.tailscaleIp ?? d.ip ?? "no address"}</option>)}
        </select>
      </div>
      {device.addressHistory.length > 1 && (
        <div><h3>Addresses</h3><div className="list small">{device.addressHistory.map((a) => <div key={a.ip}><span className="grow mono">{a.ip}</span><span className="muted">{ago(a.lastSeen)}</span></div>)}</div></div>
      )}
      <div><h3>History</h3><div className="list small">{device.events.map((e) => <div key={e.id}><span className="grow">{(eventText[e.kind] ?? (() => e.kind))(e.detail)}</span><span className="muted">{new Date(e.at).toLocaleString()}</span></div>)}</div></div>
    </section>
  );
}

const networkBadge: Record<string, string> = { lan: "b-ok", router: "b-ok", tailscale: "b-info", docker: "b-med", local: "b-med", other: "b-med", public: "b-high" };

type ActivityData = { connected: boolean; total: number; blockedTotal?: number; top: { domain: string; queries: number }[]; blocked: { domain: string; blocked: number; lists: string[] }[] };

/** What the device looked up in the last 24 hours, from Pi-hole: a clue to what it is. */
function Activity({ deviceId }: { deviceId: number }) {
  const [data, setData] = useState<ActivityData | null>(null);
  useEffect(() => { api<ActivityData>("GET", `/api/fleet/devices/${deviceId}/activity`).then(setData, () => setData(null)); }, [deviceId]);
  if (!data) return <p className="small muted">Reading Pi-hole…</p>;
  if (!data.connected) return null;
  return (
    <div className="stack" style={{ gap: 6 }}>
      <h3>Last 24 hours in Pi-hole</h3>
      {data.total === 0 ? <p className="small muted">No lookups from this address: it is quiet, uses other DNS, or Pi-hole sees it under another address.</p> : (
        <>
          <p className="small muted">{data.total.toLocaleString()} lookups{data.blockedTotal ? `, ${data.blockedTotal.toLocaleString()} blocked` : ""}. The sites it asks for most often say a lot about what it is.</p>
          <div className="list small">{data.top.slice(0, 8).map((t) => <div key={t.domain}><span className="grow mono">{t.domain}</span><span className="muted">{t.queries}</span></div>)}</div>
          {data.blocked.length > 0 && (
            <>
              <h3>Blocked for it</h3>
              <div className="list small">{data.blocked.slice(0, 8).map((b) => <div key={b.domain}><span className="grow"><span className="mono">{b.domain}</span>{b.lists.length ? <span className="muted"> · {b.lists.join(", ")}</span> : null}</span><span className="muted">{b.blocked}</span></div>)}</div>
            </>
          )}
        </>
      )}
    </div>
  );
}
