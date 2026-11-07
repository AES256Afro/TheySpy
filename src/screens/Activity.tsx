import { useCallback, useEffect, useState } from "react";
import { api, type AuditEntry, type Job, type Retention, type RetentionPolicy } from "../api.ts";

const statusBadge: Record<Job["status"], string> = { queued: "b-info", running: "b-info", succeeded: "b-ok", failed: "b-crit", interrupted: "b-high" };

function when(iso: string | null) {
  return iso ? new Date(iso).toLocaleString() : "—";
}

/** Bytes as a person reads them: "204 MB", "12.5 MB", "640 KB". */
export function sizeText(bytes: number | null): string {
  if (bytes === null) return "—";
  if (bytes >= 100 * 1048576) return `${Math.round(bytes / 1048576)} MB`;
  if (bytes >= 1048576) return `${(bytes / 1048576).toFixed(1)} MB`;
  return `${Math.max(1, Math.round(bytes / 1024))} KB`;
}

/** Which tables are the mirrors and libraries (bounded by their sources), as against what grows with use. */
const bounded: Record<string, string> = { cves: "the CVE mirror (every CVE NVD lists, kept because an old router has old CVEs)", blocklist_versions: "the blocklist library (the last two versions of each list)", oui: "the MAC vendor registry", cves_published: "the CVE mirror's index", cves_epss: "exploit-likelihood scores", cves_kev: "known-exploited entries" };

function HouseholdCard() {
  const [set, setSet] = useState<boolean | null>(null);
  const [password, setPassword] = useState("");
  const [note, setNote] = useState<{ tone: "good" | "bad"; text: string } | null>(null);
  const load = useCallback(() => api<{ set: boolean }>("GET", "/api/household").then((r) => setSet(r.set), () => setSet(null)), []);
  useEffect(() => { void load(); }, [load]);
  const act = async (fn: () => Promise<unknown>, done: string) => {
    try { await fn(); setNote({ tone: "good", text: done }); setPassword(""); await load(); } catch (e) { setNote({ tone: "bad", text: e instanceof Error ? e.message : String(e) }); }
  };
  if (set === null) return null;
  return (
    <section className="card" aria-labelledby="household-heading">
      <header><h2 id="household-heading">Household</h2><span className="muted small">{set ? "a household password is set" : "no household password"}</span></header>
      <p className="small">A second password that opens the Overview, Checks, Fleet and the device pages, and This device, and changes nothing: for the family to look without being able to touch Pi-hole, the lists or the settings. Who signed in with it is in the audit log.</p>
      <div className="row">
        <input className="input" type="password" autoComplete="new-password" aria-label="Household password" placeholder={set ? "type to replace (8+ characters)" : "8 characters or more"} value={password} onChange={(e) => setPassword(e.target.value)} />
        <button className="btn primary" type="button" disabled={password.length < 8} onClick={() => act(() => api("PUT", "/api/household", { password }), set ? "Replaced; the household signs in again with the new one." : "Set. The household can sign in with it now.")}>{set ? "Replace" : "Set"}</button>
        {set && <button className="btn" type="button" onClick={() => act(() => api("DELETE", "/api/household"), "Cleared; household sessions are ended.")}>Clear</button>}
        {note && <span className={`small${note.tone === "bad" ? "" : " muted"}`} role={note.tone === "bad" ? "alert" : undefined}>{note.text}</span>}
      </div>
    </section>
  );
}

const policyOrder: (keyof RetentionPolicy)[] = ["hits", "audit", "jobs", "checks", "events", "reports"];

function DatabaseCard({ retention, onChange }: { retention: Retention | null; onChange: () => Promise<void> }) {
  const [draft, setDraft] = useState<Record<string, string>>({});
  const [failed, setFailed] = useState("");
  const [saved, setSaved] = useState(false);
  if (!retention) return null;
  const { size, policy, labels, limits } = retention;
  const heaviest = size.tables.filter((t) => t.bytes !== null).slice(0, 6);
  const edited = Object.keys(draft).length > 0;
  const save = async () => {
    setFailed(""); setSaved(false);
    try {
      await api("PUT", "/api/retention", Object.fromEntries(Object.entries(draft).map(([k, v]) => [k, Number(v)])));
      setDraft({}); setSaved(true);
      await onChange();
    } catch (e) { setFailed(e instanceof Error ? e.message : String(e)); }
  };
  const trimNow = async () => {
    setFailed("");
    try { await api("POST", "/api/jobs", { kind: "retention.trim" }); await onChange(); } catch (e) { setFailed(e instanceof Error ? e.message : String(e)); }
  };
  return (
    <section className="card" aria-labelledby="database-heading">
      <header><h2 id="database-heading">Database</h2><span className="muted small">{sizeText(size.bytes)} on disk{size.free > 0 ? `, ${sizeText(size.free)} of it free inside the file` : ""}</span></header>
      <p className="small">
        {heaviest.length > 0 && <>Heaviest: {heaviest.map((t, i) => <span key={t.name}>{i > 0 ? ", " : ""}<span className="mono">{t.name}</span> {sizeText(t.bytes)}{bounded[t.name] ? ` (${bounded[t.name]})` : ""}</span>)}. </>}
        The mirrors and the library are bounded by their sources; what grows with use is trimmed once a day to the days below.
        {size.lastTrim ? ` Last trimmed ${when(size.lastTrim.at)}: ${Object.values(size.lastTrim.removed).reduce((a, b) => a + b, 0)} record(s) removed${size.lastTrim.compacted ? ", and the file compacted" : ""}.` : " Not trimmed yet."}
      </p>
      <div className="table-wrap"><table>
        <thead><tr><th>Kept</th><th>Days</th></tr></thead>
        <tbody>{policyOrder.map((key) => (
          <tr key={key}><td><label htmlFor={`retention-${key}`}>{labels[key]}</label></td>
            <td><input id={`retention-${key}`} className="input" type="number" min={limits.min} max={limits.max} step={1} style={{ width: "7em" }} value={draft[key] ?? String(policy[key])} onChange={(e) => setDraft({ ...draft, [key]: e.target.value })} /></td></tr>
        ))}</tbody>
      </table></div>
      <div className="row">
        <button className="btn primary" type="button" onClick={save} disabled={!edited}>Save</button>
        <button className="btn" type="button" onClick={trimNow} title="Runs the daily trim now, as a job">Trim now</button>
        {saved && <span className="muted small">Saved.</span>}
        {failed && <span className="small" role="alert">{failed}</span>}
      </div>
    </section>
  );
}

type SecurityNote = { id: string; title: string; detail: string; fix: string };

export function ActivityScreen() {
  const [jobs, setJobs] = useState<Job[]>([]);
  const [audit, setAudit] = useState<AuditEntry[]>([]);
  const [notes, setNotes] = useState<SecurityNote[]>([]);
  const [retention, setRetention] = useState<Retention | null>(null);
  const [error, setError] = useState("");

  const load = useCallback(async () => {
    try {
      const [j, a, s, r] = await Promise.all([api<{ jobs: Job[] }>("GET", "/api/jobs"), api<{ entries: AuditEntry[] }>("GET", "/api/audit"), api<{ notes: SecurityNote[] }>("GET", "/api/security"), api<Retention>("GET", "/api/retention")]);
      setJobs(j.jobs);
      setAudit(a.entries);
      setNotes(s.notes);
      setRetention(r);
      setError("");
    } catch (failure) {
      setError(failure instanceof Error ? failure.message : String(failure));
    }
  }, []);

  useEffect(() => { void load(); }, [load]);
  const busy = jobs.some((job) => job.status === "queued" || job.status === "running");
  useEffect(() => {
    if (!busy) return;
    const timer = setInterval(load, 1000);
    return () => clearInterval(timer);
  }, [busy, load]);

  const runTestJob = async () => {
    await api("POST", "/api/jobs", { kind: "noop" });
    await load();
  };

  return (
    <div className="stack">
      <div className="top">
        <div><h1>Activity</h1><p className="muted small">Jobs and the audit log.</p></div>
        <div className="grow" />
        <a className="btn" href="/api/backup" title="A checked copy of TheySpy's database, taken while it runs. Restore by stopping TheySpy and putting it in place of data/theyspy.db; stored passwords need the same TS_SESSION_SECRET.">Download a backup</a>
        <button className="btn primary" type="button" onClick={runTestJob} disabled={busy}>Run a test job</button>
      </div>
      {error && <div className="banner bad" role="alert">{error}</div>}
      {notes.map((note) => (
        <div className="banner warn" key={note.id}>
          <strong>{note.title}</strong>
          <p className="small">{note.detail}</p>
          <p className="small">{note.fix}</p>
        </div>
      ))}
      <HouseholdCard />
      <DatabaseCard retention={retention} onChange={load} />
      <section className="card">
        <header><h2>Jobs</h2><span className="muted small">newest first</span></header>
        {jobs.length === 0 ? <p className="muted small">No jobs yet. “Run a test job” checks that the runner works.</p> : (
          <div className="table-wrap"><table>
            <thead><tr><th>#</th><th>Job</th><th>Status</th><th>By</th><th>Queued</th><th>Finished</th></tr></thead>
            <tbody>{jobs.map((job) => (
              <tr key={job.id}><td className="mono">{job.id}</td><td>{job.title}<div className="muted small mono">{job.kind}</div></td>
                <td><span className={`badge ${statusBadge[job.status]}`}>{job.status}</span></td><td>{job.actor}</td><td className="small">{when(job.created_at)}</td><td className="small">{when(job.finished_at)}</td></tr>
            ))}</tbody>
          </table></div>
        )}
      </section>
      <section className="card">
        <header><h2>Audit log</h2><span className="muted small">last 100 entries</span></header>
        <div className="table-wrap"><table>
          <thead><tr><th>When</th><th>Who</th><th>What</th><th>Target</th></tr></thead>
          <tbody>{audit.map((entry) => (
            <tr key={entry.id}><td className="small">{when(entry.at)}</td><td className="mono">{entry.actor}</td><td className="mono">{entry.action}</td><td className="mono small">{entry.target ?? ""}</td></tr>
          ))}</tbody>
        </table></div>
      </section>
    </div>
  );
}
