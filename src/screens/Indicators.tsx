import { useCallback, useEffect, useMemo, useState } from "react";
import { api, lastLogLine, waitForJob, type Job } from "../api.ts";

type Provenance = { track: "bundled" | "release" | "main"; release?: string; signedBy?: string; signedAt?: string; sha256?: string; note: string };
type Version = { id: number; status: "pending" | "active" | "superseded" | "rejected"; sha256: string; asof: string | null; count: number; provenance: Provenance; fetchedAt: string; decidedAt: string | null; decidedBy: string | null; changes?: { added: number; removed: number; changed: number } };
type Indicator = { value: string; type: "domain" | "ip" | "sha256"; tier: string; confidence: string; source: string; citation?: string };
type Diff = { added: Indicator[]; removed: Indicator[]; changed: { value: string; fields: { field: string; from: string; to: string }[] }[]; asof: { from: string | null; to: string | null } };
type Overview = {
  active: Version | null;
  pending: Version | null;
  counts: { total: number; byType: Record<string, number>; byTier: Record<string, number> };
  track: "release" | "main";
  lastCheck: { at: string; track: string; outcome: "up-to-date" | "update-found" | "failed"; message?: string } | null;
  tiers: Record<string, string>;
  exports: { id: string; file: string; label: string }[];
};

const tierBadge: Record<string, string> = { cc: "b-crit", validator: "b-crit", sample: "b-crit", candiru: "b-high", delivery: "b-med", "candiru-ip": "b-low", historical: "b-low", "vuln-driver": "b-info" };
const typeLabel: Record<string, string> = { domain: "Domains", ip: "IP addresses", sha256: "File hashes" };
const fingerprint = (fp?: string) => (fp ? fp.match(/.{1,4}/g)!.join(" ") : "");
const when = (iso?: string | null) => (iso ? new Date(iso).toLocaleString() : "—");

function Trust({ version }: { version: Version }) {
  const p = version.provenance;
  const label = p.track === "main" ? "Integrity checked only" : p.track === "release" ? `Signed release ${p.release}` : `Bundled, matches signed ${p.release}`;
  return (
    <div className="stack" style={{ gap: 8 }}>
      <div className="row"><span className={`badge ${p.track === "main" ? "b-high" : "b-ok"}`}>{label}</span><span className="small muted">{p.note}</span></div>
      {p.signedBy && <div className="small">Signed by <code>{fingerprint(p.signedBy)}</code> on {when(p.signedAt)}</div>}
      <div className="small muted">SHA-256 <code>{version.sha256}</code></div>
    </div>
  );
}

function DiffLists({ diff }: { diff: Diff }) {
  const [all, setAll] = useState(false);
  const cut = <T,>(items: T[]) => (all ? items : items.slice(0, 15));
  const more = Math.max(diff.added.length, diff.removed.length, diff.changed.length) > 15;
  return (
    <div className="stack" style={{ gap: 10 }}>
      <div className="grid g3">
        <div><h3>Added ({diff.added.length})</h3><div className="list small">{cut(diff.added).map((i) => <div key={i.value}><code className="grow">{i.value}</code><span className={`badge ${tierBadge[i.tier] ?? "b-info"}`}>{i.tier}</span></div>)}</div></div>
        <div><h3>Removed ({diff.removed.length})</h3><div className="list small">{cut(diff.removed).map((i) => <div key={i.value}><code className="grow">{i.value}</code><span className={`badge ${tierBadge[i.tier] ?? "b-info"}`}>{i.tier}</span></div>)}</div></div>
        <div><h3>Changed ({diff.changed.length})</h3><div className="list small">{cut(diff.changed).map((c) => <div key={c.value}><code className="grow">{c.value}</code><span className="muted">{c.fields.map((f) => `${f.field}: ${f.from} → ${f.to}`).join(", ")}</span></div>)}</div></div>
      </div>
      {more && <button className="btn small" type="button" onClick={() => setAll(!all)}>{all ? "Show fewer" : "Show every change"}</button>}
    </div>
  );
}

export function IndicatorsScreen() {
  const [overview, setOverview] = useState<Overview | null>(null);
  const [indicators, setIndicators] = useState<Indicator[]>([]);
  const [pendingDiff, setPendingDiff] = useState<Diff | null>(null);
  const [history, setHistory] = useState<Version[]>([]);
  const [busy, setBusy] = useState("");
  const [message, setMessage] = useState<{ tone: "good" | "bad" | "warn"; text: string } | null>(null);
  const [query, setQuery] = useState("");
  const [type, setType] = useState("all");
  const [tier, setTier] = useState("all");
  const [limit, setLimit] = useState(100);

  const load = useCallback(async () => {
    const [o, list, h] = await Promise.all([api<Overview>("GET", "/api/iocs"), api<{ indicators: Indicator[] }>("GET", "/api/iocs/indicators"), api<{ versions: Version[] }>("GET", "/api/iocs/versions")]);
    setOverview(o);
    setIndicators(list.indicators);
    setHistory(h.versions);
    setPendingDiff(o.pending ? (await api<{ version: { diff: Diff } }>("GET", `/api/iocs/versions/${o.pending.id}`)).version.diff : null);
  }, []);
  useEffect(() => { load().catch((e: Error) => setMessage({ tone: "bad", text: e.message })); }, [load]);

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
  const check = () => run("check", () => api("POST", "/api/iocs/check"));
  const apply = (id: number) => run("apply", () => api("POST", `/api/iocs/versions/${id}/apply`));
  const reject = async (id: number) => { await api("POST", `/api/iocs/versions/${id}/reject`); setMessage({ tone: "warn", text: "Update rejected. The active set is unchanged." }); await load(); };
  const setTrack = async (track: string) => { await api("PUT", "/api/iocs/settings", { track }); await load(); };

  const filtered = useMemo(() => {
    const q = query.trim().toLowerCase().replace(/\[\.\]/g, ".");
    return indicators.filter((i) => (type === "all" || i.type === type) && (tier === "all" || i.tier === tier) && (!q || i.value.replace(/\[\.\]/g, ".").includes(q) || i.source.includes(q)));
  }, [indicators, query, type, tier]);

  if (!overview) return <div className="stack"><h1>Indicators</h1>{message && <div className="banner bad">{message.text}</div>}</div>;
  const { active, pending, counts } = overview;

  return (
    <div className="stack">
      <div className="top">
        <div><h1>Indicators</h1><p className="muted small">zero-breach’s AdFection / Candiru set · as-of {active?.asof ?? "undated"} · {counts.total} indicators. A hit means investigate, never “you are compromised”.</p></div>
        <div className="grow" />
        <button className="btn primary" type="button" onClick={check} disabled={Boolean(busy)}>{busy === "check" ? "Checking…" : "Check for updates"}</button>
      </div>
      {message && <div className={`banner ${message.tone}`} role="status"><span className="small">{message.text}</span></div>}

      {pending && (
        <section className="card stack" style={{ borderColor: "var(--high)" }}>
          <header><h2>Update waiting for review</h2><span className="badge b-high">pending</span></header>
          <div className="small">Found {when(pending.fetchedAt)}: <b>+{pending.changes?.added} new</b>, <b>−{pending.changes?.removed} removed</b>, <b>~{pending.changes?.changed} changed</b>{pendingDiff?.asof.from !== pendingDiff?.asof.to && <> · curated {pendingDiff?.asof.from ?? "undated"} → {pendingDiff?.asof.to ?? "undated"}</>}.</div>
          <Trust version={pending} />
          {pendingDiff && <DiffLists diff={pendingDiff} />}
          <div className="row">
            <button className="btn primary" type="button" onClick={() => apply(pending.id)} disabled={Boolean(busy)}>{busy === "apply" ? "Applying…" : "Apply this update"}</button>
            <button className="btn" type="button" onClick={() => reject(pending.id)} disabled={Boolean(busy)}>Reject</button>
          </div>
        </section>
      )}

      <div className="grid g2">
        <section className="card stack">
          <header><h2>Where this set came from</h2></header>
          {active ? <Trust version={active} /> : <p className="muted small">No set is active.</p>}
          <div className="field">
            <span className="label" id="track-label">Update from</span>
            <div className="seg" role="group" aria-labelledby="track-label">
              <button type="button" aria-pressed={overview.track === "release"} onClick={() => setTrack("release")}>Signed releases</button>
              <button type="button" aria-pressed={overview.track === "main"} onClick={() => setTrack("main")}>Latest on main</button>
            </div>
            <span className="hint">{overview.track === "release" ? "Each release’s checksum list must be signed by ArchiveGenocide’s pinned key. Slower to arrive, proven to come from the publisher." : "Newest changes, checked only against a hash served from the same place. Proves the download is intact, not who published it."}</span>
          </div>
          <p className="small muted">Last check: {overview.lastCheck ? `${when(overview.lastCheck.at)} (${overview.lastCheck.track}) — ${overview.lastCheck.outcome === "failed" ? `failed: ${overview.lastCheck.message}` : overview.lastCheck.outcome.replace("-", " ")}` : "never"}. TheySpy also checks once a day and only ever offers an update for review.</p>
        </section>

        <section className="card stack">
          <header><h2>Export</h2><span className="muted small">identical to zero-breach’s own files</span></header>
          <div className="list small">
            {overview.exports.map((e) => (
              <div key={e.id}><span className="grow">{e.label}<div className="muted"><code>{e.file}</code></div></span><a className="btn small" href={`/api/iocs/export/${e.id}`} download={e.file}>Download</a></div>
            ))}
          </div>
          <p className="small muted">Blocklists leave out IP addresses (mostly reassigned cloud hosts) and file hashes. The STIX bundle works with Amnesty’s Mobile Verification Toolkit for checking phones.</p>
        </section>
      </div>

      <section className="card">
        <header><h2>Tiers</h2><span className="muted small">what a hit on each kind means</span></header>
        <div className="table-wrap"><table>
          <tbody>{Object.entries(overview.tiers).filter(([t]) => counts.byTier[t]).map(([t, description]) => (
            <tr key={t}><td><span className={`badge ${tierBadge[t] ?? "b-info"}`}>{t}</span></td><td className="mono">{counts.byTier[t]}</td><td className="small">{description}</td></tr>
          ))}</tbody>
        </table></div>
      </section>

      <section className="card">
        <header>
          <h2>All indicators</h2>
          <span className="muted small">{filtered.length} shown · defanged so nothing here is clickable or fetchable</span>
        </header>
        <div className="row" style={{ marginBottom: 12 }}>
          <input className="input" style={{ maxWidth: 320 }} placeholder="Search value or source…" value={query} onChange={(e) => { setQuery(e.target.value); setLimit(100); }} aria-label="Search indicators" />
          <div className="seg" role="group" aria-label="Type">
            {["all", "domain", "ip", "sha256"].map((t) => <button key={t} type="button" aria-pressed={type === t} onClick={() => { setType(t); setLimit(100); }}>{t === "all" ? "All" : typeLabel[t]} {t !== "all" && `(${counts.byType[t] ?? 0})`}</button>)}
          </div>
          <select className="input" style={{ maxWidth: 180 }} value={tier} onChange={(e) => { setTier(e.target.value); setLimit(100); }} aria-label="Tier">
            <option value="all">All tiers</option>
            {Object.keys(counts.byTier).sort().map((t) => <option key={t} value={t}>{t}</option>)}
          </select>
        </div>
        <div className="table-wrap"><table>
          <thead><tr><th>Indicator</th><th>Tier</th><th>Confidence</th><th>Source</th></tr></thead>
          <tbody>{filtered.slice(0, limit).map((i) => (
            <tr key={i.value}><td className="mono" style={{ wordBreak: "break-all" }}>{i.value}</td><td><span className={`badge ${tierBadge[i.tier] ?? "b-info"}`}>{i.tier}</span></td><td className="small">{i.confidence}</td><td className="small">{i.citation}</td></tr>
          ))}</tbody>
        </table></div>
        {filtered.length > limit && <button className="btn small" type="button" style={{ marginTop: 10 }} onClick={() => setLimit(limit + 200)}>Show more ({filtered.length - limit} left)</button>}
      </section>

      <section className="card">
        <header><h2>History</h2><span className="muted small">every version fetched, kept with its raw file</span></header>
        <div className="table-wrap"><table>
          <thead><tr><th>#</th><th>Status</th><th>As-of</th><th>Count</th><th>From</th><th>Fetched</th><th>Decided</th></tr></thead>
          <tbody>{history.map((v) => (
            <tr key={v.id}><td className="mono">{v.id}</td><td><span className={`badge ${v.status === "active" ? "b-ok" : v.status === "pending" ? "b-high" : v.status === "rejected" ? "b-crit" : "b-info"}`}>{v.status}</span></td><td>{v.asof ?? "—"}</td><td className="mono">{v.count}</td><td className="small">{v.provenance.track}{v.provenance.release ? ` ${v.provenance.release}` : ""}</td><td className="small">{when(v.fetchedAt)}</td><td className="small">{v.decidedBy ? `${v.decidedBy}, ${when(v.decidedAt)}` : "—"}</td></tr>
          ))}</tbody>
        </table></div>
      </section>
    </div>
  );
}
