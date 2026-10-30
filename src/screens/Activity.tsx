import { useCallback, useEffect, useState } from "react";
import { api, type AuditEntry, type Job } from "../api.ts";

const statusBadge: Record<Job["status"], string> = { queued: "b-info", running: "b-info", succeeded: "b-ok", failed: "b-crit", interrupted: "b-high" };

function when(iso: string | null) {
  return iso ? new Date(iso).toLocaleString() : "—";
}

export function ActivityScreen() {
  const [jobs, setJobs] = useState<Job[]>([]);
  const [audit, setAudit] = useState<AuditEntry[]>([]);
  const [error, setError] = useState("");

  const load = useCallback(async () => {
    try {
      const [j, a] = await Promise.all([api<{ jobs: Job[] }>("GET", "/api/jobs"), api<{ entries: AuditEntry[] }>("GET", "/api/audit")]);
      setJobs(j.jobs);
      setAudit(a.entries);
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
        <div><h1>Activity</h1><p className="muted small">Every job and every change, with who did it and when.</p></div>
        <div className="grow" />
        <a className="btn" href="/api/backup" title="A checked copy of TheySpy's database, taken while it runs. Restore by stopping TheySpy and putting it in place of data/theyspy.db; stored passwords need the same TS_SESSION_SECRET.">Download a backup</a>
        <button className="btn primary" type="button" onClick={runTestJob} disabled={busy}>Run a test job</button>
      </div>
      {error && <div className="banner bad" role="alert">{error}</div>}
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
