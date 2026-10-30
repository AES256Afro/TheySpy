import { useCallback, useEffect, useState } from "react";
import { api } from "../api.ts";

type Site = {
  id: string; name: string; url: string; at: string | null; error?: string | null; errorAt?: string;
  version?: string | null; lookups?: number; online?: number; exploited?: number;
  gotThrough?: { device: string; indicator: string; lookups: number; blocked: number; lastSeen: string | null }[];
  sections?: { title: string; tone: string; lines: string[] }[];
};
const toneBadge: Record<string, string> = { good: "b-ok", warn: "b-med", bad: "b-crit", unknown: "b-info" };
const ago = (iso?: string | null) => (iso ? new Date(iso).toLocaleString() : "never");

export function SitesScreen() {
  const [sites, setSites] = useState<Site[] | null>(null);
  const [form, setForm] = useState({ name: "", url: "", token: "" });
  const [busy, setBusy] = useState(false);
  const [message, setMessage] = useState<{ tone: "good" | "bad"; text: string } | null>(null);
  const load = useCallback(async () => setSites((await api<{ sites: Site[] }>("GET", "/api/sites")).sites), []);
  useEffect(() => { load().catch((e: Error) => setMessage({ tone: "bad", text: e.message })); }, [load]);
  const act = async (fn: () => Promise<unknown>, done: string) => {
    setBusy(true); setMessage(null);
    try { await fn(); setMessage({ tone: "good", text: done }); await load(); } catch (e) { setMessage({ tone: "bad", text: e instanceof Error ? e.message : String(e) }); } finally { setBusy(false); }
  };

  if (!sites) return <div className="stack"><h1>Sites</h1>{message ? <div className="banner bad">{message.text}</div> : <p className="muted small">Loading…</p>}</div>;
  return (
    <div className="stack">
      <div className="top">
        <div><h1>Sites</h1><p className="muted small">Other places you run TheySpy (a cabin, a parents&apos; house), read through each one&apos;s read-only API every 15 minutes. This TheySpy can see them but change nothing there. A lookup that gets past a site&apos;s blocking alerts you here.</p></div>
        <div className="grow" />
        {sites.length > 0 && <button className="btn" type="button" disabled={busy} onClick={() => act(() => api("POST", "/api/sites/refresh"), "Read every site.")}>{busy ? "Reading…" : "Read now"}</button>}
      </div>
      {message && <div className={`banner ${message.tone}`} role="status"><span className="small">{message.text}</span></div>}

      {sites.map((s) => (
        <section key={s.id} className="card stack">
          <header><h2>{s.name}</h2><span className="muted small">{s.url}{s.version ? ` · TheySpy ${s.version}` : ""} · read {ago(s.at)}</span><span className="grow" />
            <button className="btn small danger" type="button" onClick={() => act(() => api("DELETE", `/api/sites/${s.id}`), `Removed ${s.name}.`)}>Remove</button></header>
          {s.error && <div className="banner bad"><span className="small">Could not read it {ago(s.errorAt)}: {s.error}. {s.at ? "Below is its last reading." : ""}</span></div>}
          {s.at && (
            <>
              <div className="grid g3">
                <div><h3>Got past blocking</h3><div className={`kpi ${s.gotThrough?.length ? "crit" : ""}`}>{s.gotThrough?.length ?? 0}</div><p className="small muted">of {s.lookups ?? 0} indicator lookups this week</p></div>
                <div><h3>Exploited bugs</h3><div className="kpi">{s.exploited ?? 0}</div><p className="small muted">in software on its devices</p></div>
                <div><h3>Online</h3><div className="kpi">{s.online ?? 0}</div><p className="small muted">devices now</p></div>
              </div>
              {(s.gotThrough ?? []).length > 0 && <div className="list small">{s.gotThrough!.map((l) => <div key={`${l.device}-${l.indicator}`}><span className="badge b-crit">reached</span><span className="grow"><b>{l.device}</b> <span className="mono">{l.indicator}</span> · {l.lookups - l.blocked} of {l.lookups} not blocked</span><span className="muted">{ago(l.lastSeen)}</span></div>)}</div>}
              <div className="list small">{(s.sections ?? []).map((sec) => <div key={sec.title} style={{ alignItems: "flex-start" }}><span className={`badge ${toneBadge[sec.tone] ?? "b-info"}`}>{sec.title}</span><span className="grow muted">{sec.lines.join(" ")}</span></div>)}</div>
            </>
          )}
        </section>
      ))}

      <section className="card stack">
        <h3>Add a site</h3>
        <p className="small muted">In the other TheySpy: Briefing → API and MCP → create a token. Paste its address and the token here; it is stored encrypted. The token is read-only, so this TheySpy can never change that site.</p>
        <div className="compact-fields">
          <div className="field"><label htmlFor="site-name">Name</label><input id="site-name" className="input" placeholder="Cabin" value={form.name} onChange={(e) => setForm({ ...form, name: e.target.value })} /></div>
          <div className="field"><label htmlFor="site-url">Address</label><input id="site-url" className="input" placeholder="https://cabin.example.ts.net:8797" value={form.url} onChange={(e) => setForm({ ...form, url: e.target.value })} /></div>
          <div className="field"><label htmlFor="site-token">API token</label><input id="site-token" className="input" type="password" autoComplete="off" placeholder="tsy_…" value={form.token} onChange={(e) => setForm({ ...form, token: e.target.value })} /></div>
        </div>
        <div><button className="btn primary" type="button" disabled={busy} onClick={() => act(async () => { await api("POST", "/api/sites", form); setForm({ name: "", url: "", token: "" }); await api("POST", "/api/sites/refresh"); }, "Added; first reading taken.")}>Add and read</button></div>
      </section>
    </div>
  );
}
