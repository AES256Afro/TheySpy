import { useCallback, useEffect, useState } from "react";
import { api, lastLogLine, waitForJob, type Job } from "../api.ts";

type Cve = {
  cveId: string; published: string | null; description: string | null; cvss: number | null; severity: string | null; vector: string | null; cwes: string[]; products: string[];
  kev: { added: string; due: string | null; ransomware: boolean; name: string | null; action: string | null } | null;
  epss: number | null; epssPercentile: number | null; zeroDay: boolean; zeroDaySources: { source: string; at: string | null; note: string | null }[];
};
type Feed = { at?: string; version?: string; count?: number; added?: number; through?: string; fetched?: number; progress?: { done: number; total: number } | null; scoreDate?: string; scores?: number; updated?: number } | null;
type Overview = {
  total: number; rows: Cve[];
  stats: { total: number; kev: number; zeroDays: number; epssHigh: number; kevThisWeek: number; feeds: { kev: Feed; nvd: Feed; epss: Feed }; apiKey: boolean;
    errors?: Record<string, { at: string; error: string }>; nvdKey?: { configured: boolean; rejected: boolean; rejectedAt: string | null; message: string | null } };
  events: { cveId: string; at: string; kind: string; detail: Record<string, unknown>; title: string | null }[];
  attributions: string[];
  research: { source: string; title: string; url: string; at: string | null; cves: string[] }[];
  advisories: { at: string; exploited: number; added: number; errors: string[] } | null;
};

const severityBadge: Record<string, string> = { critical: "b-crit", high: "b-high", medium: "b-med", low: "b-low" };
const n = (x: number) => x.toLocaleString();
function ago(iso?: string) {
  if (!iso) return "never";
  const s = Math.max(0, (Date.now() - Date.parse(iso)) / 1000);
  return s < 90 ? "just now" : s < 3600 ? `${Math.round(s / 60)} min ago` : s < 172800 ? `${Math.round(s / 3600)} h ago` : `${Math.round(s / 86400)} days ago`;
}
const productLabel = (p: string) => p.split(":").map((x) => x.replace(/_/g, " ")).join(" · ");

const feedNames: Record<string, string> = { kev: "CISA KEV", nvd: "NVD", epss: "EPSS", advisories: "vendor advisories", first: "first CVE load" };

export function IntelScreen() {
  const [data, setData] = useState<Overview | null>(null);
  const [filters, setFilters] = useState({ kev: false, minEpss: "", severity: "", q: "", product: "" });
  const [page, setPage] = useState(0);
  const [busy, setBusy] = useState(false);
  const [message, setMessage] = useState<{ tone: "good" | "bad"; text: string } | null>(null);

  const load = useCallback(async () => {
    const p = new URLSearchParams({ limit: "50", offset: String(page * 50) });
    if (filters.kev) p.set("kev", "1");
    if (filters.minEpss) p.set("minEpss", filters.minEpss);
    if (filters.severity) p.set("severity", filters.severity);
    if (filters.q.trim()) p.set("q", filters.q.trim());
    if (filters.product.trim()) p.set("product", filters.product.trim());
    setData(await api<Overview>("GET", `/api/cves?${p}`));
  }, [filters, page]);
  useEffect(() => { load().catch((e: Error) => setMessage({ tone: "bad", text: e.message })); }, [load]);

  const update = async () => {
    setBusy(true);
    setMessage(null);
    try {
      const { job } = await api<{ job: Job }>("POST", "/api/cves/update");
      const done = await waitForJob(job.id);
      setMessage({ tone: done.status === "succeeded" ? "good" : "bad", text: lastLogLine(done) || done.status });
      await load();
    } catch (error) {
      setMessage({ tone: "bad", text: error instanceof Error ? error.message : String(error) });
    } finally {
      setBusy(false);
    }
  };
  const set = (patch: Partial<typeof filters>) => { setPage(0); setFilters({ ...filters, ...patch }); };

  if (!data) return <div className="stack"><h1>CVEs &amp; zero-days</h1>{message ? <div className="banner bad">{message.text}</div> : <p className="muted small">Loading…</p>}</div>;
  const { stats } = data;
  const feeds = stats.feeds;

  return (
    <div className="stack">
      <div className="top">
        <div><h1>CVEs &amp; zero-days</h1><p className="muted small">{n(stats.total)} CVEs · {n(stats.zeroDays)} exploited ({n(stats.kev)} in CISA KEV, the rest reported by vendors) · exploited ones first. The ones in software on your devices are on each device's Targeted check, and you get an alert when one appears.</p></div>
        <div className="grow" />
        <button className="btn primary" type="button" disabled={busy} onClick={update}>{busy ? "Updating…" : "Update now"}</button>
      </div>
      {message && <div className={`banner ${message.tone}`} role="status"><span className="small">{message.text}</span></div>}
      {stats.nvdKey?.rejected && (
        <div className="banner bad" role="alert"><span className="small">NVD refused the API key ({stats.nvdKey.message ?? "invalid"}), so TheySpy is reading NVD without it: slower, but nothing is missed. Check the key (it must be activated from NVD&apos;s e-mail), or clear it, in TheySpy&apos;s settings (BoxPilot: the app&apos;s Settings → NVD API key). TheySpy tries it again a day after it was refused.</span></div>
      )}
      {Object.entries(stats.errors ?? {}).map(([feed, problem]) => (
        <div key={feed} className="banner bad" role="alert"><span className="small">The {feedNames[feed] ?? feed} feed failed {ago(problem.at)}: {problem.error}. TheySpy tries again on its schedule; Update now tries at once.</span></div>
      ))}

      <div className="grid g4">
        <section className="card"><h3>Known exploited</h3><div className="kpi crit">{n(stats.kev)}</div><p className="small muted">CISA KEV · {stats.kevThisWeek} added this week</p></section>
        <section className="card"><h3>CISA KEV</h3><div className="kpi">{feeds.kev?.version ?? "—"}</div><p className="small muted">checked {ago(feeds.kev?.at)}</p></section>
        <section className="card"><h3>NVD 2.0</h3><div className="kpi">{feeds.nvd?.through ? n(feeds.nvd.fetched ?? 0) : feeds.nvd?.progress ? `${Math.round((feeds.nvd.progress.done / Math.max(1, feeds.nvd.progress.total)) * 100)}%` : "—"}</div>
          <p className="small muted">{feeds.nvd?.through ? `last run fetched these · ${ago(feeds.nvd.at)}` : feeds.nvd?.progress ? "first load in progress" : "not loaded yet"}{stats.apiKey ? (stats.nvdKey?.rejected ? " · API key refused" : " · API key") : ""}</p></section>
        <section className="card"><h3>EPSS</h3><div className="kpi">{feeds.epss?.scoreDate ?? "—"}</div><p className="small muted">{feeds.epss ? `${n(feeds.epss.scores ?? 0)} scores · ${stats.epssHigh} here ≥ 0.5` : "not loaded yet"}</p></section>
      </div>

      {stats.total === 0 && <div className="banner warn"><span className="small">Nothing loaded yet. The first update fetches CISA KEV, the last 120 days of NVD (a few minutes without an NVD API key) and today’s EPSS scores; it starts by itself shortly after TheySpy starts, or press Update now.</span></div>}

      <div className="two-col">
        <section className="card stack">
          <div className="row">
            <input className="input" style={{ maxWidth: 260 }} placeholder="CVE id, product or words…" value={filters.q} onChange={(e) => set({ q: e.target.value })} aria-label="Search CVEs" />
            <label className="small row" style={{ gap: 6 }}><input type="checkbox" checked={filters.kev} onChange={(e) => set({ kev: e.target.checked })} />Known exploited only</label>
            <select className="input" style={{ maxWidth: 150 }} value={filters.minEpss} onChange={(e) => set({ minEpss: e.target.value })} aria-label="EPSS at least">
              <option value="">Any EPSS</option>{["0.1", "0.5", "0.9"].map((v) => <option key={v} value={v}>EPSS ≥ {v}</option>)}
            </select>
            <select className="input" style={{ maxWidth: 140 }} value={filters.severity} onChange={(e) => set({ severity: e.target.value })} aria-label="Severity">
              <option value="">Any severity</option>{["critical", "high", "medium", "low"].map((v) => <option key={v} value={v}>{v}</option>)}
            </select>
          </div>
          <p className="small muted">{n(data.total)} match · sorted exploited first, newest KEV additions on top, then by EPSS.</p>
          <div className="list">{data.rows.map((c) => (
            <div key={c.cveId} style={{ alignItems: "flex-start" }}>
              <div className="grow stack" style={{ gap: 4 }}>
                <div className="row" style={{ gap: 6 }}>
                  {c.zeroDay && <span className="badge b-crit">EXPLOITED</span>}
                  <a className="mono" href={`https://nvd.nist.gov/vuln/detail/${c.cveId}`} target="_blank" rel="noreferrer noopener"><b>{c.cveId}</b></a>
                  {c.cvss !== null && <span className={`badge ${severityBadge[c.severity ?? ""] ?? "b-info"}`}>CVSS {c.cvss}</span>}
                  {c.kev && <span className="badge b-high">KEV · due {c.kev.due ?? "—"}</span>}
                  {c.kev?.ransomware && <span className="badge b-crit">ransomware</span>}
                  {c.epss !== null && <span className="badge b-info" title={`percentile ${Math.round((c.epssPercentile ?? 0) * 100)}`}>EPSS {c.epss.toFixed(2)}</span>}
                </div>
                {c.kev?.name && <b className="small">{c.kev.name}</b>}
                {c.zeroDaySources.filter((z) => z.source !== "CISA KEV").length > 0 && <span className="small">{c.zeroDaySources.filter((z) => z.source !== "CISA KEV").map((z) => z.note).join(" · ")}</span>}
                <span className="small muted">{(c.description ?? "").slice(0, 260)}{(c.description ?? "").length > 260 ? "…" : ""}</span>
                <span className="small">{c.products.slice(0, 4).map(productLabel).join(" · ")}{c.products.length > 4 ? ` and ${c.products.length - 4} more` : ""}</span>
              </div>
            </div>
          ))}</div>
          <div className="row">
            <button className="btn small" type="button" disabled={page === 0} onClick={() => setPage(page - 1)}>Previous</button>
            <span className="small muted">page {page + 1} of {Math.max(1, Math.ceil(data.total / 50))}</span>
            <button className="btn small" type="button" disabled={(page + 1) * 50 >= data.total} onClick={() => setPage(page + 1)}>Next</button>
          </div>
        </section>
        <div className="stack sticky">
          <section className="card stack">
            <h3>Recent changes</h3>
            {data.events.length === 0 ? <p className="small muted">New KEV entries and new CVEs appear here after the first load.</p> : (
              <div className="list small">{data.events.map((e) => (
                <div key={`${e.cveId}-${e.at}-${e.kind}`}><span className="grow"><b className="mono">{e.cveId}</b> <span className="muted">{e.kind === "kev_added" ? "added to KEV" : "new"}{e.title ? ` · ${e.title.slice(0, 70)}` : ""}</span></span><span className="muted">{ago(e.at)}</span></div>
              ))}</div>
            )}
          </section>
          <section className="card stack">
            <h3>Research reports</h3>
            {data.research.length === 0 ? <p className="small muted">Citizen Lab and Amnesty Security Lab reports appear here after the next update.</p> : (
              <div className="list small">{data.research.slice(0, 8).map((r) => (
                <div key={r.url} style={{ alignItems: "flex-start" }}><span className="grow"><a href={r.url} target="_blank" rel="noreferrer noopener">{r.title}</a><br /><span className="muted">{r.source}{r.at ? ` · ${r.at}` : ""}{r.cves.length ? ` · ${r.cves.join(", ")}` : ""}</span></span></div>
              ))}</div>
            )}
          </section>
          <section className="card stack">
            <h3>Sources</h3>
            <p className="small muted">Exploitation reports: CISA KEV, Chrome Releases, Apple security releases and Microsoft (MSRC){data.advisories ? `, checked ${ago(data.advisories.at)}` : ""}.{data.advisories?.errors.length ? ` Problems: ${data.advisories.errors.join("; ")}` : ""}</p>
            <ul className="small muted" style={{ margin: 0, paddingLeft: 18 }}>{data.attributions.map((a) => <li key={a}>{a}</li>)}</ul>
            {!stats.apiKey && <p className="small muted">Set <code>TS_NVD_API_KEY</code> (free from NVD) for faster updates.</p>}
          </section>
        </div>
      </div>
    </div>
  );
}
