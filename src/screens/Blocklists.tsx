import { useCallback, useEffect, useState, type FormEvent } from "react";
import { api, lastLogLine, waitForJob, type Job } from "../api.ts";

type Source = {
  id: number; key: string; directory: string; name: string; description: string | null; url: string | null; homepage: string | null; license: string | null; syntax: string | null;
  categories: string[]; curated: boolean; status: "candidate" | "enabled" | "disabled"; lastCheckedAt: string | null; lastChangedAt: string | null;
  failures: number; lastError: string | null; entries: number | null; health: string;
};
type Category = { id: string; group: string; name: string; description: string; domains: number; lists: number };
type Held = { id: number; sourceId: number; name: string; count: number; added: number; removed: number; sample: { added: string[]; removed: string[]; risky: string[] }; reasons: string[]; fetchedAt: string };
type Overview = {
  sources: Source[]; quarantined: Held[]; categories: Category[]; groups: Record<string, string>; candidateCount: number;
  lastDiscovery: { at: string; added: number; seen: number; errors: string[] } | null;
  lastUpdate: { at: string; lists: number; first: number; updated: number; unchanged: number; quarantined: number; failed: number } | null;
  pins: string[];
  subscriptions: { id: string; name: string; description: string; url: string; domains: number }[];
  formats: { id: string; label: string }[];
  listsBaseUrl: string; listsBaseUrlSet: boolean;
  pihole: { connected: boolean; write: boolean };
};
type PiholeSubscription = { address: string; entries: number; status: number; enabled: boolean; updated: string | null };

const directoryLabel: Record<string, string> = { builtin: "built in", adguard: "AdGuard registry", filterlists: "FilterLists", firebog: "Firebog", custom: "added by you" };
const healthBadge: Record<string, string> = { ok: "b-ok", stale: "b-med", dead: "b-crit", deprecated: "b-high", "not fetched": "b-info" };
const when = (iso?: string | null) => (iso ? new Date(iso).toLocaleString() : "—");
const n = (x: number | null | undefined) => (x === null || x === undefined ? "—" : x.toLocaleString());

function CategoryChips({ ids, all }: { ids: string[]; all: Category[] }) {
  return <span className="row" style={{ gap: 4 }}>{ids.map((id) => <span key={id} className={`badge ${all.find((c) => c.id === id)?.group === "security" ? "b-crit" : all.find((c) => c.id === id)?.group === "privacy" ? "b-info" : "b-med"}`}>{all.find((c) => c.id === id)?.name ?? id}</span>)}</span>;
}

export function BlocklistsScreen() {
  const [overview, setOverview] = useState<Overview | null>(null);
  const [candidates, setCandidates] = useState<{ total: number; candidates: Source[] }>({ total: 0, candidates: [] });
  const [search, setSearch] = useState({ q: "", category: "", directory: "" });
  const [busy, setBusy] = useState("");
  const [message, setMessage] = useState<{ tone: "good" | "bad" | "warn"; text: string } | null>(null);
  const [custom, setCustom] = useState({ url: "", name: "", categories: [] as string[] });
  const [pins, setPins] = useState("");
  const [baseUrl, setBaseUrl] = useState("");
  const [subscribed, setSubscribed] = useState<{ subscriptions: PiholeSubscription[]; error?: string } | null>(null);

  const load = useCallback(async () => {
    const o = await api<Overview>("GET", "/api/blocklists");
    setOverview(o);
    setPins(o.pins.join("\n"));
    setBaseUrl(o.listsBaseUrl);
    if (o.pihole.connected) setSubscribed(await api("GET", "/api/blocklists/pihole"));
  }, []);
  const loadCandidates = useCallback(async () => {
    const params = new URLSearchParams(Object.entries(search).filter(([, v]) => v));
    setCandidates(await api("GET", `/api/blocklists/candidates?${params}`));
  }, [search]);
  useEffect(() => { load().catch((e: Error) => setMessage({ tone: "bad", text: e.message })); }, [load]);
  useEffect(() => { loadCandidates().catch(() => {}); }, [loadCandidates]);

  const run = async (label: string, start: () => Promise<{ job: Job }>) => {
    setBusy(label);
    setMessage(null);
    try {
      const done = await waitForJob((await start()).job.id);
      setMessage({ tone: done.status === "succeeded" ? "good" : "bad", text: lastLogLine(done) || done.status });
      await Promise.all([load(), loadCandidates()]);
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
      await Promise.all([load(), loadCandidates()]);
    } catch (error) {
      setMessage({ tone: "bad", text: error instanceof Error ? error.message : String(error) });
    }
  };
  const setStatus = (s: Source, status: string) => act(() => api("PUT", `/api/blocklists/sources/${s.id}`, { status }), status === "enabled" ? `${s.name} is on and being fetched.` : `${s.name} is off.`);
  const addCustom = (e: FormEvent) => {
    e.preventDefault();
    void act(async () => { await api("POST", "/api/blocklists/sources", custom); setCustom({ url: "", name: "", categories: [] }); }, "Added; it is being fetched now.");
  };

  if (!overview) return <div className="stack"><h1>Blocklist library</h1>{message ? <div className="banner bad">{message.text}</div> : <p className="muted small">Loading…</p>}</div>;
  const { sources, quarantined, categories, groups } = overview;
  const enabled = sources.filter((s) => s.status === "enabled");
  const unhealthy = enabled.filter((s) => s.health !== "ok");
  const recommended = overview.subscriptions.find((s) => s.id === "recommended");

  return (
    <div className="stack">
      <div className="top">
        <div><h1>Blocklist library</h1><p className="muted small">Every DNS blocklist TheySpy knows about, sorted into categories and kept up to date. New lists are found automatically and wait for you; updates that look wrong are held for review.</p></div>
        <div className="grow" />
        <button className="btn" type="button" disabled={Boolean(busy)} onClick={() => run("discover", () => api("POST", "/api/blocklists/discover"))}>{busy === "discover" ? "Looking…" : "Discover now"}</button>
        <button className="btn primary" type="button" disabled={Boolean(busy)} onClick={() => run("update", () => api("POST", "/api/blocklists/update"))}>{busy === "update" ? "Updating…" : "Update lists"}</button>
      </div>
      {message && <div className={`banner ${message.tone}`} role="status"><span className="small">{message.text}</span></div>}

      <div className="grid g3">
        <section className="card"><h3>Enabled lists</h3><div className="kpi">{enabled.length}</div><p className="small muted">{n(recommended?.domains)} domains in Recommended · last update {when(overview.lastUpdate?.at)}</p></section>
        <section className="card"><h3>Candidates</h3><div className="kpi">{n(overview.candidateCount)}</div><p className="small muted">{overview.lastDiscovery ? `${overview.lastDiscovery.added} new at the last look, ${when(overview.lastDiscovery.at)}` : "Not looked yet."}{overview.lastDiscovery?.errors.length ? ` Problems: ${overview.lastDiscovery.errors.join("; ")}` : ""}</p></section>
        <section className="card"><h3>Needs a look</h3><div className="kpi" style={{ color: quarantined.length || unhealthy.length ? "var(--high)" : "var(--ok)" }}>{quarantined.length + unhealthy.length}</div><p className="small muted">{quarantined.length} updates held · {unhealthy.length} lists stale, dead or never fetched</p></section>
      </div>

      {quarantined.map((h) => (
        <section key={h.id} className="card stack" style={{ borderColor: "var(--high)" }}>
          <header><h2>Update held: {h.name}</h2><span className="badge b-high">review</span></header>
          <ul className="small" style={{ margin: 0 }}>{h.reasons.map((r) => <li key={r}>{r}</li>)}</ul>
          <div className="small muted">Fetched {when(h.fetchedAt)}: {n(h.count)} entries, +{n(h.added)} added, −{n(h.removed)} removed.</div>
          {h.sample.risky.length > 0 && <div className="list small">{h.sample.risky.map((d) => <div key={d}><code className="grow">{d}</code><span className="badge b-crit">protected</span></div>)}</div>}
          <div className="row">
            <button className="btn" type="button" onClick={() => act(() => api("POST", `/api/blocklists/versions/${h.id}/accept`), "Accepted; protected names still stay off the compiled lists.")}>Accept this update</button>
            <button className="btn primary" type="button" onClick={() => act(() => api("POST", `/api/blocklists/versions/${h.id}/reject`), "Rejected; the previous version stays in use.")}>Keep the previous version</button>
          </div>
        </section>
      ))}

      <div className="grid g3">
        {Object.entries(groups).map(([group, label]) => (
          <section key={group} className="card">
            <header><h2>{label}</h2></header>
            <div className="list small">{categories.filter((c) => c.group === group).map((c) => (
              <div key={c.id} title={c.description}><span className="grow">{c.name}</span><span className="mono muted">{c.lists ? `${n(c.domains)} · ${c.lists} list${c.lists === 1 ? "" : "s"}` : "no list on"}</span></div>
            ))}</div>
          </section>
        ))}
      </div>

      <section className="card">
        <header><h2>Lists in use</h2><span className="muted small">{sources.length} enabled or turned off</span></header>
        <div className="table-wrap"><table>
          <thead><tr><th>List</th><th>Categories</th><th>Entries</th><th>Changed</th><th>Health</th><th></th></tr></thead>
          <tbody>{sources.map((s) => (
            <tr key={s.id} style={{ opacity: s.status === "enabled" ? 1 : 0.6 }}>
              <td><b>{s.name}</b><div className="muted small">{directoryLabel[s.directory] ?? s.directory}{s.license ? ` · ${s.license}` : ""}{s.homepage && <> · <a href={s.homepage} target="_blank" rel="noreferrer noopener">home</a></>}</div></td>
              <td><CategoryChips ids={s.categories} all={categories} /></td>
              <td className="mono">{s.directory === "builtin" ? "from Indicators" : n(s.entries)}</td>
              <td className="small">{when(s.lastChangedAt)}</td>
              <td><span className={`badge ${healthBadge[s.health] ?? "b-info"}`} title={s.lastError ?? ""}>{s.health}</span></td>
              <td>{s.directory !== "builtin" && (s.status === "enabled" ? <button className="btn small" type="button" onClick={() => setStatus(s, "disabled")}>Turn off</button> : <button className="btn small" type="button" onClick={() => setStatus(s, "enabled")}>Turn on</button>)}</td>
            </tr>
          ))}</tbody>
        </table></div>
      </section>

      <section className="card stack">
        <header><h2>Find more lists</h2><span className="muted small">{n(candidates.total)} candidates from AdGuard’s registry, FilterLists and Firebog</span></header>
        <div className="row">
          <input className="input" style={{ maxWidth: 280 }} placeholder="Search names and descriptions…" value={search.q} onChange={(e) => setSearch({ ...search, q: e.target.value })} aria-label="Search candidates" />
          <select className="input" style={{ maxWidth: 200 }} value={search.category} onChange={(e) => setSearch({ ...search, category: e.target.value })} aria-label="Category">
            <option value="">All categories</option>{categories.map((c) => <option key={c.id} value={c.id}>{c.name}</option>)}
          </select>
          <select className="input" style={{ maxWidth: 200 }} value={search.directory} onChange={(e) => setSearch({ ...search, directory: e.target.value })} aria-label="Directory">
            <option value="">All directories</option>{["adguard", "filterlists", "firebog"].map((d) => <option key={d} value={d}>{directoryLabel[d]}</option>)}
          </select>
        </div>
        <div className="table-wrap"><table>
          <tbody>{candidates.candidates.map((c) => (
            <tr key={c.id}>
              <td><b>{c.name}</b> {c.curated && <span className="badge b-ok">curated</span>}<div className="muted small">{directoryLabel[c.directory]}{c.license ? ` · ${c.license}` : ""}{c.syntax ? ` · ${c.syntax}` : ""}</div>{c.description && <div className="small muted" style={{ maxWidth: 560 }}>{c.description.slice(0, 180)}</div>}</td>
              <td><CategoryChips ids={c.categories} all={categories} /></td>
              <td><button className="btn small" type="button" onClick={() => setStatus(c, "enabled")}>Turn on</button></td>
            </tr>
          ))}</tbody>
        </table></div>
        {candidates.total > candidates.candidates.length && <p className="small muted">Showing the first {candidates.candidates.length}; narrow the search to see others.</p>}
      </section>

      <div className="grid g2">
        <section className="card stack">
          <header><h2>Subscribe Pi-hole to TheySpy</h2></header>
          <p className="small muted">{overview.pihole.connected
            ? <>Pi-hole downloads each list it subscribes to on every gravity update, so it always gets TheySpy’s compiled, checked version.{!overview.pihole.write && " Allow TheySpy to change Pi-hole (Pi-hole Sentinel) to add them from here."}</>
            : <>In Pi-hole: Lists → add an address, then update gravity. Connect Pi-hole on the Pi-hole Sentinel screen to do it from here.</>}
            {" "}For other filters change <code>.txt</code> to <code>.hosts</code>, <code>.adblock</code>, <code>.dnsmasq</code> or <code>.rpz</code>. Keep these addresses private.</p>
          <div className="field">
            <label htmlFor="lists-base">TheySpy’s address</label>
            <div className="row"><input id="lists-base" className="input" style={{ maxWidth: 300 }} value={baseUrl} onChange={(e) => setBaseUrl(e.target.value)} />
              <button className="btn small" type="button" onClick={() => act(() => api("PUT", "/api/blocklists/base-url", { url: baseUrl }), "Saved the address Pi-hole will use.")}>Save</button></div>
            <span className="hint">As Pi-hole reaches it, e.g. http://192.168.1.5:8797. {overview.listsBaseUrlSet ? "Set by you." : "Taken from this page’s address; change it if Pi-hole sees TheySpy differently."}</span>
          </div>
          {subscribed?.error && <div className="banner warn"><span className="small">Could not read Pi-hole’s lists: {subscribed.error}</span></div>}
          <div className="list small">{overview.subscriptions.filter((s) => s.domains > 0).map((s) => {
            const inPihole = subscribed?.subscriptions.find((p) => p.address === s.url);
            return (
              <div key={s.id}><span className="grow"><b>{s.name}</b> <span className="muted">{n(s.domains)} domains</span>
                {inPihole && <span className="badge b-ok" style={{ marginLeft: 6 }}>in Pi-hole · {n(inPihole.entries)}</span>}
                <div className="mono muted" style={{ wordBreak: "break-all" }}>{s.url}</div></span>
                {overview.pihole.connected && overview.pihole.write && (inPihole
                  ? <button className="btn small" type="button" disabled={Boolean(busy)} onClick={() => run(`unsub-${s.id}`, () => api("DELETE", "/api/blocklists/pihole", { address: s.url }))}>{busy === `unsub-${s.id}` ? "Removing…" : "Remove from Pi-hole"}</button>
                  : <button className="btn small primary" type="button" disabled={Boolean(busy)} onClick={() => run(`sub-${s.id}`, () => api("POST", `/api/blocklists/pihole/${s.id}`))}>{busy === `sub-${s.id}` ? "Adding…" : "Add to Pi-hole"}</button>)}
                <button className="btn small" type="button" onClick={() => { void navigator.clipboard?.writeText(s.url); setMessage({ tone: "good", text: `Copied the ${s.name} address.` }); }}>Copy</button></div>
            );
          })}</div>
        </section>

        <div className="stack">
          <section className="card">
            <header><h2>Add a list by address</h2></header>
            <form className="stack" onSubmit={addCustom}>
              <input className="input" placeholder="https://example.com/blocklist.txt" value={custom.url} onChange={(e) => setCustom({ ...custom, url: e.target.value })} required aria-label="List address" />
              <input className="input" placeholder="Name (optional)" value={custom.name} onChange={(e) => setCustom({ ...custom, name: e.target.value })} aria-label="List name" />
              <div className="row" role="group" aria-label="Categories">{categories.map((c) => (
                <label key={c.id} className="small row" style={{ gap: 4 }}><input type="checkbox" checked={custom.categories.includes(c.id)} onChange={(e) => setCustom({ ...custom, categories: e.target.checked ? [...custom.categories, c.id] : custom.categories.filter((x) => x !== c.id) })} />{c.name}</label>
              ))}</div>
              <div><button className="btn" type="submit">Add and fetch</button></div>
            </form>
          </section>
          <section className="card stack">
            <header><h2>Never block</h2></header>
            <p className="small muted">Names no list may take away, on top of TheySpy’s own (connectivity checks, certificates, time and updates) and the sites your network uses most. One per line.</p>
            <textarea className="input mono" rows={5} value={pins} onChange={(e) => setPins(e.target.value)} aria-label="Never-block names" />
            <div><button className="btn" type="button" onClick={() => act(() => api("PUT", "/api/blocklists/pins", { pins: pins.split(/\s+/).filter(Boolean) }), "Saved.")}>Save</button></div>
          </section>
        </div>
      </div>
    </div>
  );
}
