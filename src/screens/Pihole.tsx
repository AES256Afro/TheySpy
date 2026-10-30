import { useCallback, useEffect, useState, type FormEvent } from "react";
import { useNames } from "../names.ts";
import { api, lastLogLine, waitForJob, type Job } from "../api.ts";

type Config = {
  configured: boolean; mode: Mode | null; url: string | null; username: string | null; dbPath: string | null; write: boolean; watch: boolean; windowDays: number; canWrite: boolean; limits: string | null;
  hasPassword: boolean; passwordUnreadable: boolean; fromEnv: { url: boolean; password: boolean; dbPath: boolean; write: boolean };
};
type Overview = {
  config: Config;
  lastTest: { ok: boolean; message?: string; where?: string; core?: string; ftl?: string; queries?: number; since?: string | null; at: string } | null;
  lastHunt: { mode: string; from: string; until: string; indicators: number; queriesSeen: number; newHits: number; finishedAt: string } | null;
  watch: { enabled: boolean; running: boolean; lastPollAt: string | null; lastError: string | null; newHits: number };
  coverage: { at: string; stale: boolean; asof: string | null; total: number; blocked: number; fullyBlocked: number; allowlisted: number; notFullyBlocked: { domain: string; blocked: boolean; subdomainsBlocked: boolean; allowlisted: boolean; by: string[] }[] } | null;
  preview: { checkedAt: string; count: number; domains: string[]; skippedAllowlisted: string[]; token: string } | null;
  pushes: { id: number; status: "active" | "rolled_back"; entries: number; pushedAt: string; pushedBy: string; rolledBackAt: string | null }[];
};
type Hit = { indicator: string; domain: string; via: "query" | "cname"; clientIp: string; clientName: string | null; firstSeen: string; lastSeen: string; lookups: number; blocked: number; lastStatus: string; tier: string | null; citation: string | null };

const tierBadge: Record<string, string> = { cc: "b-crit", validator: "b-crit", candiru: "b-high", delivery: "b-med", historical: "b-low" };
const when = (iso?: string | null) => (iso ? new Date(iso).toLocaleString() : "—");

type Mode = "api" | "database" | "adguard" | "technitium" | "opnsense";

// The DNS servers TheySpy reads lookups from. Pi-hole's API can also change lists; the others are read-only.
const sources: Record<Mode, { label: string; address?: string; addressHint?: string; user?: string; userHint?: string; secret?: string; secretHint?: string }> = {
  api: { label: "Pi-hole 6", address: "http://192.168.1.5:8084", addressHint: "Where Pi-hole’s web interface answers. On BoxPilot that is this server on port 8084 (bridge mode) or 80 (host mode).", secret: "Password", secretHint: "An app password (Pi-hole → Settings → Web interface / API) is best: it can be revoked on its own." },
  database: { label: "Pi-hole database file" },
  adguard: { label: "AdGuard Home", address: "http://192.168.1.5:3000", addressHint: "Where AdGuard Home’s web interface answers.", user: "User", userHint: "AdGuard Home’s own sign-in.", secret: "Password", secretHint: "TheySpy only reads the query log, statistics and client names." },
  technitium: { label: "Technitium", address: "http://192.168.1.5:5380", addressHint: "Where Technitium’s web console answers. It needs a query-log app: Apps → App Store → Query Logs (Sqlite).", secret: "API token", secretHint: "Administration → Sessions → Create Token; a user that can view logs and the dashboard is enough." },
  opnsense: { label: "OPNsense (Unbound)", address: "https://192.168.1.1", addressHint: "OPNsense’s address. Turn on Services → Unbound DNS → General → Statistics so it keeps a query log.", user: "API key", userHint: "System → Access → Users → API keys.", secret: "API secret", secretHint: "The secret that came with the key." },
};

function ConnectForm({ config, onSaved }: { config: Config; onSaved: (text: string) => void }) {
  const [mode, setMode] = useState<Mode>(config.mode ?? "api");
  const [url, setUrl] = useState(config.url ?? "");
  const [username, setUsername] = useState(config.username ?? "");
  const [password, setPassword] = useState("");
  const [dbPath, setDbPath] = useState(config.dbPath ?? "/pihole/pihole-FTL.db");
  const [error, setError] = useState("");
  const kind = sources[mode];
  // The Pi-hole variables in the environment fix Pi-hole's own settings only.
  const envUrl = mode === "api" && config.fromEnv.url;
  const envPassword = mode === "api" && config.fromEnv.password;
  const save = async (event: FormEvent) => {
    event.preventDefault();
    setError("");
    try {
      const body: Record<string, unknown> = { mode };
      if (mode === "database") { if (!config.fromEnv.dbPath) body.dbPath = dbPath; }
      else {
        if (!envUrl) body.url = url;
        if (kind.user) body.username = username;
        if (password && !envPassword) body.password = password;
      }
      await api("PUT", "/api/pihole/settings", body);
      setPassword("");
      const job = await waitForJob((await api<{ job: Job }>("POST", "/api/pihole/test")).job.id);
      onSaved(job.status === "succeeded" ? lastLogLine(job) : `Saved, but the connection failed: ${lastLogLine(job)}`);
    } catch (failure) {
      setError(failure instanceof Error ? failure.message : String(failure));
    }
  };
  return (
    <form className="stack" onSubmit={save}>
      <div className="seg" role="group" aria-label="Which DNS server to read">
        {(Object.keys(sources) as Mode[]).map((m) => <button key={m} type="button" aria-pressed={mode === m} onClick={() => setMode(m)}>{sources[m].label}</button>)}
      </div>
      {mode === "database" ? (
        <div className="field"><label htmlFor="ph-db">Database path</label><input id="ph-db" className="input" value={dbPath} disabled={config.fromEnv.dbPath} onChange={(e) => setDbPath(e.target.value)} required />
          <span className="hint">pihole-FTL.db mounted read-only into TheySpy (Pi-hole 5 or 6). Hunts and the live watch work; the coverage check and pushes need the API.</span></div>
      ) : (
        <>
          <div className="field"><label htmlFor="ph-url">Address</label><input id="ph-url" className="input" placeholder={kind.address} value={url} disabled={envUrl} onChange={(e) => setUrl(e.target.value)} required />
            <span className="hint">{envUrl ? "Set by TS_PIHOLE_URL." : kind.addressHint}</span></div>
          {kind.user && <div className="field"><label htmlFor="ph-user">{kind.user}</label><input id="ph-user" className="input" autoComplete="off" value={username} onChange={(e) => setUsername(e.target.value)} required />
            <span className="hint">{kind.userHint}</span></div>}
          <div className="field"><label htmlFor="ph-pass">{kind.secret}</label><input id="ph-pass" className="input" type="password" autoComplete="off" placeholder={config.hasPassword && config.mode === mode ? "Saved (leave empty to keep)" : kind.secret} value={password} disabled={envPassword} onChange={(e) => setPassword(e.target.value)} />
            <span className="hint">{envPassword ? "Set by TS_PIHOLE_PASSWORD." : `${kind.secretHint} Stored encrypted; never shown again.`}</span></div>
          {mode !== "api" && <span className="small muted">Read-only: TheySpy hunts and watches {kind.label}’s lookups. Adding blocks, subscribing to lists and baselines need Pi-hole.</span>}
        </>
      )}
      {config.passwordUnreadable && <div className="banner warn"><span className="small">The saved password can no longer be read (the session secret changed). Enter it again.</span></div>}
      {error && <div className="banner bad" role="alert"><span className="small">{error}</span></div>}
      <div><button className="btn primary" type="submit">Save and test</button></div>
    </form>
  );
}

export function PiholeScreen() {
  const names = useNames();
  const [overview, setOverview] = useState<Overview | null>(null);
  const [hits, setHits] = useState<Hit[]>([]);
  const [busy, setBusy] = useState("");
  const [message, setMessage] = useState<{ tone: "good" | "bad" | "warn"; text: string } | null>(null);
  const [editing, setEditing] = useState(false);
  const [showAll, setShowAll] = useState(false);

  const load = useCallback(async () => {
    const [o, h] = await Promise.all([api<Overview>("GET", "/api/pihole"), api<{ hits: Hit[] }>("GET", "/api/pihole/hits")]);
    setOverview(o);
    setHits(h.hits);
  }, []);
  useEffect(() => { load().catch((e: Error) => setMessage({ tone: "bad", text: e.message })); }, [load]);
  useEffect(() => {
    const timer = setInterval(() => { void load().catch(() => {}); }, 30_000);
    return () => clearInterval(timer);
  }, [load]);

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
  const setFlag = async (flag: "write" | "watch", value: boolean) => { await api("PUT", "/api/pihole/settings", { [flag]: value }); await load(); };

  if (!overview) return <div className="stack"><h1>Pi-hole Sentinel</h1>{message && <div className="banner bad">{message.text}</div>}</div>;
  const { config, lastTest, lastHunt, watch, coverage, preview, pushes } = overview;
  const answered = hits.reduce((n, h) => n + h.lookups - h.blocked, 0);
  const isApi = config.mode === "api";

  return (
    <div className="stack">
      <div className="top">
        <div>
          <h1>Pi-hole Sentinel</h1>
          <p className="muted small">
            {config.configured
              ? <>{lastTest?.ok ? <>Connected to {lastTest.where}{lastTest.ftl ? ` · FTL ${lastTest.ftl}` : ""}</> : lastTest ? <>Last test failed: {lastTest.message}</> : "Not tested yet"} · <button className="btn small" type="button" onClick={() => setEditing(!editing)}>{editing ? "Close settings" : "Settings"}</button></>
              : "Connect Pi-hole, AdGuard Home, Technitium or OPNsense to hunt its DNS history for spyware and ad-intelligence lookups."}
          </p>
        </div>
        <div className="grow" />
        {config.configured && <>
          <button className="btn" type="button" disabled={Boolean(busy)} onClick={() => run("hunt", () => api("POST", "/api/pihole/hunt", {}))}>{busy === "hunt" ? "Hunting…" : `Hunt last ${config.windowDays} days`}</button>
          {isApi && <button className="btn primary" type="button" disabled={Boolean(busy)} onClick={() => run("coverage", () => api("POST", "/api/pihole/coverage"))}>{busy === "coverage" ? "Checking…" : "Check coverage"}</button>}
        </>}
      </div>
      {message && <div className={`banner ${message.tone}`} role="status"><span className="small">{message.text}</span></div>}

      {(!config.configured || editing) && (
        <section className="card">
          <header><h2>{config.configured ? "Connection" : "Connect your DNS server"}</h2></header>
          {config.limits && <p className="small muted">{config.limits}</p>}
          <ConnectForm config={config} onSaved={(text) => { setEditing(false); setMessage({ tone: "good", text }); void load(); }} />
          {config.configured && (
            <div className="field">
              <label htmlFor="ph-window">Hunt window</label>
              <select id="ph-window" className="input" value={config.windowDays} onChange={async (e) => { await api("PUT", "/api/pihole/settings", { windowDays: Number(e.target.value) }); await load(); }}>
                {[7, 30, 90, 180, 365].map((d) => <option key={d} value={d}>{d} days</option>)}
              </select>
              <span className="hint">How far back a hunt looks. Pi-hole keeps 91 days by default.</span>
            </div>
          )}
        </section>
      )}

      {config.configured && (
        <>
          {answered > 0 && (
            <div className="banner bad">
              <span className="badge b-crit">answered</span>
              <span className="small grow"><b>{answered} indicator {answered === 1 ? "lookup was" : "lookups were"} answered by Pi-hole</b>, so the device could reach that server. A lookup is not proof of infection; it means investigate that device. {isApi && preview && preview.count > 0 && "Blocking the indicator domains below stops the next one."}</span>
            </div>
          )}

          <div className="grid g3">
            <section className="card">
              <h3>Indicator lookups</h3>
              <div className="kpi" style={{ color: hits.length ? "var(--crit)" : "var(--ok)" }}>{hits.reduce((n, h) => n + h.lookups, 0)}</div>
              <p className="small muted">{new Set(hits.map((h) => h.clientIp)).size} devices · {new Set(hits.map((h) => h.indicator)).size} indicators{lastHunt ? ` · last hunt ${when(lastHunt.finishedAt)}, ${lastHunt.queriesSeen} queries` : " · no hunt yet"}</p>
            </section>
            <section className="card">
              <h3>Coverage</h3>
              <div className="kpi" style={{ opacity: coverage?.stale ? 0.5 : 1 }}>{coverage ? `${coverage.fullyBlocked}/${coverage.total}` : "—"}</div>
              <p className="small muted">{coverage?.stale ? "Out of date: Pi-hole changed since this check. Check again." : coverage ? `indicator domains blocked with their subdomains · ${coverage.blocked} blocked by name · checked ${when(coverage.at)}` : isApi ? "Run “Check coverage”." : "Needs the Pi-hole API."}</p>
            </section>
            <section className="card">
              <h3>Live watch</h3>
              <div className="kpi" style={{ color: watch.lastError ? "var(--high)" : undefined }}>{config.watch ? (watch.lastError ? "Error" : "On") : "Off"}</div>
              <p className="small muted">{watch.lastError ?? (watch.lastPollAt ? `Checked ${when(watch.lastPollAt)} · ${watch.newHits} new since start` : "Checks new queries every 30 seconds.")}</p>
              <button className="btn small" type="button" onClick={() => setFlag("watch", !config.watch)}>{config.watch ? "Turn off" : "Turn on"}</button>
            </section>
          </div>

          <section className="card">
            <header><h2>Indicator lookups</h2><span className="muted small">defanged · grouped by device and name</span></header>
            {hits.length === 0 ? <p className="muted small">{lastHunt ? `None in the last ${config.windowDays} days. That is good news, not a clearance: indicators get replaced, and a device can resolve names somewhere other than Pi-hole.` : "Run a hunt to look back through Pi-hole’s history."}</p> : (
              <div className="table-wrap"><table>
                <thead><tr><th>Device</th><th>Looked up</th><th>Indicator</th><th>Lookups</th><th>Pi-hole</th><th>Last seen</th></tr></thead>
                <tbody>{hits.map((h) => (
                  <tr key={`${h.clientIp}|${h.domain}|${h.via}`}>
                    <td><b>{names[h.clientIp]?.name ?? h.clientName ?? h.clientIp}</b><div className="muted small"><span className="mono">{h.clientIp}</span>{names[h.clientIp] ? ` · ${names[h.clientIp].network ?? ""} · name from ${names[h.clientIp].from}` : ""}</div></td>
                    <td className="mono" style={{ wordBreak: "break-all" }}>{h.domain}{h.via === "cname" && <div className="muted small">through a CNAME</div>}</td>
                    <td>{h.tier && <span className={`badge ${tierBadge[h.tier] ?? "b-info"}`}>{h.tier}</span>}<div className="muted small">{h.citation}</div></td>
                    <td className="mono">{h.lookups}</td>
                    <td>{h.blocked === h.lookups ? <span className="badge b-ok">blocked</span> : h.blocked ? <span className="badge b-high">{h.lookups - h.blocked} answered</span> : <span className="badge b-crit">answered</span>}</td>
                    <td className="small">{when(h.lastSeen)}{h.firstSeen !== h.lastSeen && <div className="muted">first {when(h.firstSeen)}</div>}</td>
                  </tr>
                ))}</tbody>
              </table></div>
            )}
          </section>

          {isApi && coverage && !coverage.stale && (
            <section className="card stack">
              <header><h2>Block what your lists miss</h2><span className="muted small">indicator set as-of {coverage.asof ?? "undated"}</span></header>
              {preview && preview.count > 0 ? (
                <>
                  <p className="small">Pi-hole does not fully block <b>{preview.count}</b> of {coverage.total} indicator domains. TheySpy can add one wildcard deny entry for each (the domain and every subdomain), commented <code>TheySpy:</code> so a rollback removes exactly these.{preview.skippedAllowlisted.length > 0 && <> {preview.skippedAllowlisted.length} are on your allowlist and are left alone.</>}</p>
                  <div className="list small">{(showAll ? preview.domains : preview.domains.slice(0, 12)).map((d) => <div key={d}><code className="grow">{d}</code><span className="muted">and subdomains</span></div>)}</div>
                  {preview.count > 12 && <button className="btn small" type="button" onClick={() => setShowAll(!showAll)}>{showAll ? "Show fewer" : `Show all ${preview.count}`}</button>}
                  <div className="row">
                    {config.write
                      ? <button className="btn primary" type="button" disabled={Boolean(busy)} onClick={() => run("push", () => api("POST", "/api/pihole/push", { token: preview.token }))}>{busy === "push" ? "Adding…" : `Add ${preview.count} entries to Pi-hole`}</button>
                      : <><span className="small muted">Changing Pi-hole is off.</span>{!config.fromEnv.write && <button className="btn" type="button" onClick={() => setFlag("write", true)}>Allow TheySpy to change Pi-hole’s denylist</button>}</>}
                  </div>
                </>
              ) : <div className="banner good"><span className="small">Every indicator domain is blocked, with its subdomains, by your lists or TheySpy’s entries.</span></div>}
            </section>
          )}

          {pushes.length > 0 && (
            <section className="card">
              <header><h2>Changes TheySpy made to Pi-hole</h2></header>
              <div className="table-wrap"><table>
                <thead><tr><th>#</th><th>Entries</th><th>Added</th><th>Status</th><th></th></tr></thead>
                <tbody>{pushes.map((p) => (
                  <tr key={p.id}><td className="mono">{p.id}</td><td className="mono">{p.entries}</td><td className="small">{when(p.pushedAt)} by {p.pushedBy}</td>
                    <td>{p.status === "active" ? <span className="badge b-ok">in Pi-hole</span> : <span className="badge b-info">rolled back {when(p.rolledBackAt)}</span>}</td>
                    <td>{p.status === "active" && <button className="btn small" type="button" disabled={Boolean(busy)} onClick={() => run("rollback", () => api("POST", `/api/pihole/pushes/${p.id}/rollback`))}>Roll back</button>}</td></tr>
                ))}</tbody>
              </table></div>
              {config.write && !config.fromEnv.write && <button className="btn small" type="button" style={{ marginTop: 10 }} onClick={() => setFlag("write", false)}>Stop TheySpy changing Pi-hole</button>}
            </section>
          )}
        </>
      )}
    </div>
  );
}
