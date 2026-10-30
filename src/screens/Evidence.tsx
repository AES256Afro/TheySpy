import { useCallback, useEffect, useMemo, useState, type ChangeEvent } from "react";
import { api } from "../api.ts";

type Finding = { id: number; deviceId: number | null; device: string | null; source: "agent" | "mvt" | "zeek" | "suricata"; kind: "contacted" | "gap"; indicator: string | null; tier: string | null; confidence: string | null; location: string | null; detail: string | null; at: string; status: "open" | "dismissed"; note: string | null };
type Agent = { id: number; name: string; platform: string | null; device: string | null; enrolledAt: string; lastReportAt: string | null; verdict: { status: string; hits: number; gaps: number; scanner: string | null } | null; revoked: boolean };
type Data = { findings: Finding[]; agents: Agent[]; scanner: { verified: boolean; version?: string; sha256?: string; error?: string } };
type Device = { id: number; name: string; ip: string | null };
type Fingerprint = { client: string; device: string | null; ja4: string; firstSeen: string; lastSeen: string; count: number; sni: string | null; source: string; isNew: boolean };
const sourceLabel: Record<string, string> = { agent: "agent", mvt: "MVT", zeek: "Zeek", suricata: "Suricata" };

const tierLabel: Record<string, string> = { cc: "command & control", delivery: "ad delivery", exploit: "exploit", sha256: "file hash" };
const verdictBadge: Record<string, string> = { INDICATORS_FOUND: "b-crit", NO_KNOWN_INDICATORS: "b-ok", NO_KNOWN_INDICATORS_WITH_GAPS: "b-med", NOT_RUN: "b-high" };
const verdictWord: Record<string, string> = { INDICATORS_FOUND: "indicators found", NO_KNOWN_INDICATORS: "nothing found", NO_KNOWN_INDICATORS_WITH_GAPS: "nothing found, with gaps", NOT_RUN: "scan did not run" };
const when = (iso: string | null) => (iso ? new Date(iso).toLocaleString() : "never");

export function EvidenceScreen() {
  const [data, setData] = useState<Data | null>(null);
  const [devices, setDevices] = useState<Device[]>([]);
  const [prints, setPrints] = useState<Fingerprint[]>([]);
  const [enroll, setEnroll] = useState<{ token: string; expiresAt: string } | null>(null);
  const [label, setLabel] = useState("");
  const [phone, setPhone] = useState<number | "">("");
  const [profile, setProfile] = useState({ os: "ios", osVersion: "", browser: "safari", browserVersion: "", adId: "unknown" });
  const [showDismissed, setShowDismissed] = useState(false);
  const [message, setMessage] = useState<{ tone: "good" | "bad"; text: string } | null>(null);

  const load = useCallback(async () => {
    setData(await api<Data>("GET", "/api/evidence"));
    setPrints((await api<{ fingerprints: Fingerprint[] }>("GET", "/api/evidence/fingerprints")).fingerprints);
    setDevices((await api<{ devices: (Device & { network: { kind: string } | null })[] }>("GET", "/api/fleet")).devices.filter((d) => d.network?.kind !== "docker"));
  }, []);
  useEffect(() => { load().catch((e: Error) => setMessage({ tone: "bad", text: e.message })); }, [load]);
  const act = async (fn: () => Promise<unknown>, done: string) => {
    try { await fn(); setMessage({ tone: "good", text: done }); await load(); } catch (e) { setMessage({ tone: "bad", text: e instanceof Error ? e.message : String(e) }); }
  };
  const loadProfile = async (id: number) => {
    const p = (await api<{ profile: Record<string, string> }>("GET", `/api/evidence/devices/${id}/profile`)).profile;
    setProfile({ os: p.os ?? "ios", osVersion: p.osVersion ?? "", browser: p.browser ?? "safari", browserVersion: p.browserVersion ?? "", adId: p.adId ?? "unknown" });
  };
  const importMvt = async (e: ChangeEvent<HTMLInputElement>) => {
    if (!phone || !e.target.files?.length) return;
    const files = await Promise.all([...e.target.files].map(async (f) => ({ name: f.name, content: await f.text() })));
    e.target.value = "";
    await act(async () => { const r = await api<{ findings: number }>("POST", `/api/evidence/devices/${phone}/mvt`, { files }); setMessage({ tone: "good", text: `${r.findings} new finding(s) from MVT.` }); }, "Imported.");
  };

  const importNetworkLogs = async (e: ChangeEvent<HTMLInputElement>) => {
    if (!e.target.files?.length) return;
    const files = await Promise.all([...e.target.files].map(async (f) => ({ name: f.name, content: await f.text() })));
    e.target.value = "";
    await act(async () => {
      const r = await api<{ events: number; findings: number; fingerprints: number; newFingerprints: unknown[] }>("POST", "/api/evidence/network-logs", { files });
      setMessage({ tone: r.findings || r.newFingerprints.length ? "bad" : "good", text: `Read ${r.events.toLocaleString()} DNS, TLS and HTTP records: ${r.findings} new finding(s), ${r.fingerprints} TLS fingerprint(s)${r.newFingerprints.length ? `, ${r.newFingerprints.length} new since the last import` : ""}.` });
    }, "Imported.");
  };

  const findings = useMemo(() => (data?.findings ?? []).filter((f) => showDismissed || f.status === "open"), [data, showDismissed]);
  if (!data) return <div className="stack"><h1>Evidence locker</h1>{message ? <div className="banner bad">{message.text}</div> : <p className="muted small">Loading…</p>}</div>;
  const contacted = findings.filter((f) => f.kind === "contacted");
  const gaps = findings.filter((f) => f.kind === "gap");
  const origin = window.location.origin;

  return (
    <div className="stack">
      <div className="top"><div><h1>Evidence locker</h1><p className="muted small">What the agent, MVT and your network logs found: contacts with spyware and ad-intelligence indicators, new TLS fingerprints, and every check that could not run. A gap is never counted as clean.</p></div></div>
      {message && <div className={`banner ${message.tone}`} role="status"><span className="small">{message.text}</span></div>}
      {!data.scanner.verified && <div className="banner bad"><span className="small">zero-breach’s scanner failed its signature check ({data.scanner.error}); agents will not run it.</span></div>}

      <div className="grid g3">
        <section className="card"><h3>Contacts</h3><div className={`kpi ${contacted.length ? "crit" : ""}`}>{contacted.length}</div><p className="small muted">indicators found on a device</p></section>
        <section className="card"><h3>Gaps</h3><div className="kpi">{gaps.length}</div><p className="small muted">checks that could not run</p></section>
        <section className="card"><h3>Agents</h3><div className="kpi">{data.agents.filter((a) => !a.revoked).length}</div><p className="small muted">computers reporting · scanner zero-breach {data.scanner.version ?? ""}</p></section>
      </div>

      <div className="two-col">
        <div className="stack">
          <section className="card stack">
            <header><h2>Findings</h2><label className="small row" style={{ gap: 4 }}><input type="checkbox" checked={showDismissed} onChange={(e) => setShowDismissed(e.target.checked)} />Show dismissed</label></header>
            {contacted.length === 0 ? <p className="small muted">No indicator found on any device.</p> : (
              <div className="list">{contacted.map((f) => (
                <div key={f.id} className="stack" style={{ alignItems: "stretch", gap: 4, opacity: f.status === "dismissed" ? 0.55 : 1 }}>
                  <div className="row" style={{ gap: 8 }}>
                    <span className="badge b-crit">contacted</span><b className="mono">{f.indicator}</b>
                    <span className="small muted">{f.device ?? "unknown device"} · {sourceLabel[f.source] ?? f.source}{f.tier ? ` · ${tierLabel[f.tier] ?? f.tier}` : ""}{f.confidence ? ` · ${f.confidence}` : ""}</span>
                    <span className="grow" />
                    <a className="btn small" href={`/api/evidence/findings/${f.id}/stix`}>STIX</a>
                    <button className="btn small" type="button" onClick={() => act(() => api("PUT", `/api/evidence/findings/${f.id}`, { status: f.status === "open" ? "dismissed" : "open" }), "Saved.")}>{f.status === "open" ? "Dismiss" : "Reopen"}</button>
                  </div>
                  <span className="small mono muted">{f.location}</span>
                  <span className="small muted">{f.detail} · {when(f.at)}</span>
                </div>
              ))}</div>
            )}
            {contacted.length > 0 && <p className="small">A contact means the device holds a trace of an indicator (a history entry, a cache, a file). It is strong evidence, not proof of infection: run MVT on phones, and consider expert help (Access Now’s helpline, Amnesty Security Lab).</p>}
            {prints.length > 0 && (
              <>
                <h3>TLS fingerprints (JA4)</h3>
                <p className="small muted">How each device&apos;s software opens encrypted connections, from Zeek or Suricata. A device&apos;s first import is its baseline; a fingerprint it never used before is marked new: often an update or a new app, sometimes something that should not be there.</p>
                <div className="list small">{prints.slice(0, 50).map((p) => (
                  <div key={`${p.client}-${p.ja4}`} style={{ alignItems: "flex-start" }}>
                    {p.isNew ? <span className="badge b-med">new</span> : <span className="badge b-info">known</span>}
                    <span className="grow" style={{ minWidth: 0 }}><b>{p.device ?? p.client}</b> <span className="mono" style={{ overflowWrap: "anywhere" }}>{p.ja4}</span><br /><span className="muted">{p.sni ? `first to ${p.sni} · ` : ""}{p.count} connection(s) · {when(p.firstSeen)} – {when(p.lastSeen)}</span></span>
                    {p.isNew && <button className="btn small" type="button" onClick={() => act(() => api("POST", "/api/evidence/fingerprints/acknowledge", { client: p.client, ja4: p.ja4 }), "Marked as known.")}>I know this one</button>}
                  </div>
                ))}</div>
              </>
            )}
            {gaps.length > 0 && (
              <>
                <h3>Gaps</h3>
                <div className="list small">{gaps.map((g) => <div key={g.id} style={{ alignItems: "flex-start" }}><span className="badge b-med">gap</span><span className="grow">{g.device ?? "device"}: {g.detail}</span></div>)}</div>
              </>
            )}
          </section>
        </div>

        <div className="stack sticky">
          <section className="card stack">
            <h3>Add a computer</h3>
            <p className="small muted">The agent runs zero-breach’s scanner (checked against its signed release) and reports what it found and what it could not check. Python 3.9+; Windows, macOS, Linux.</p>
            <div className="row"><input className="input grow" placeholder="Which computer, e.g. Work laptop" value={label} onChange={(e) => setLabel(e.target.value)} aria-label="Computer name" />
              <button className="btn" type="button" onClick={() => act(async () => setEnroll(await api("POST", "/api/evidence/agents/enroll", { label })), "Enrollment created.")}>Create</button></div>
            {enroll && (
              <div className="banner good stack" style={{ gap: 6 }}>
                <span className="small">On that computer, within a day (the token works once):</span>
                <code className="small">curl -fsSLo theyspy-agent.py {origin}/agent/theyspy-agent.py</code>
                <code className="small">python3 theyspy-agent.py enroll {origin} {enroll.token}</code>
                <code className="small">python3 theyspy-agent.py run</code>
                <span className="small">Schedule the last line daily (cron, launchd or Task Scheduler). On Windows use <code>py</code> instead of <code>python3</code>.</span>
              </div>
            )}
            <div className="list small">{data.agents.map((a) => (
              <div key={a.id} style={{ opacity: a.revoked ? 0.5 : 1 }}>
                <span className="grow"><b>{a.device ?? a.name}</b> <span className="muted">{a.platform ?? ""}</span><br /><span className="muted">last report {when(a.lastReportAt)}</span></span>
                {a.verdict && <span className={`badge ${verdictBadge[a.verdict.status] ?? "b-info"}`}>{verdictWord[a.verdict.status] ?? a.verdict.status}</span>}
                {!a.revoked && <button className="btn small danger" type="button" onClick={() => act(() => api("DELETE", `/api/evidence/agents/${a.id}`), "Revoked.")}>Revoke</button>}
              </div>
            ))}</div>
          </section>

          <section className="card stack">
            <h3>Network logs</h3>
            <p className="small muted">From a sensor that watches your network: Zeek&apos;s <code>dns.log</code>, <code>ssl.log</code> and <code>http.log</code> (plain or JSON), or Suricata&apos;s <code>eve.json</code>. Every name looked up, TLS server and web host is checked against the indicators, and each device&apos;s TLS fingerprints (JA4: Suricata 8 with <code>ja4-fingerprints</code> on, or Zeek with FoxIO&apos;s JA4 package) are kept. Nothing leaves TheySpy.</p>
            <label className="small">Import logs <input type="file" accept=".log,.json,.jsonl,application/json,text/plain" multiple onChange={(e) => void importNetworkLogs(e)} /></label>
          </section>

          <section className="card stack">
            <h3>Phones</h3>
            <p className="small muted">Phones cannot run the agent. Check them with Amnesty’s <a href="https://docs.mvt.re" target="_blank" rel="noreferrer noopener">MVT</a> using TheySpy’s STIX file (Indicators → Export), then import MVT’s <code>*_detected.json</code> here. Record what the phone runs so its CVEs are matched.</p>
            <select className="input" value={phone} onChange={(e) => { const id = Number(e.target.value) || ""; setPhone(id); if (id) void loadProfile(id); }} aria-label="Phone">
              <option value="">Choose the phone…</option>{devices.map((d) => <option key={d.id} value={d.id}>{d.name}{d.ip && d.name !== d.ip ? ` (${d.ip})` : ""}</option>)}
            </select>
            {phone !== "" && (
              <>
                <label className="small">Import MVT results <input type="file" accept=".json,application/json" multiple onChange={(e) => void importMvt(e)} /></label>
                <div className="compact-fields">
                  <div className="field"><label htmlFor="p-os">System</label><div className="row"><select id="p-os" className="input" style={{ maxWidth: 110 }} value={profile.os} onChange={(e) => setProfile({ ...profile, os: e.target.value })}><option value="ios">iOS</option><option value="ipados">iPadOS</option><option value="android">Android</option></select><input className="input grow" placeholder="version, e.g. 26.7.1" value={profile.osVersion} onChange={(e) => setProfile({ ...profile, osVersion: e.target.value })} aria-label="System version" /></div></div>
                  <div className="field"><label htmlFor="p-browser">Browser</label><div className="row"><select id="p-browser" className="input" style={{ maxWidth: 110 }} value={profile.browser} onChange={(e) => setProfile({ ...profile, browser: e.target.value })}><option value="safari">Safari</option><option value="chrome">Chrome</option><option value="firefox">Firefox</option><option value="brave">Brave</option><option value="edge">Edge</option></select><input className="input grow" placeholder="version" value={profile.browserVersion} onChange={(e) => setProfile({ ...profile, browserVersion: e.target.value })} aria-label="Browser version" /></div></div>
                  <div className="field"><label htmlFor="p-ad">Ad ID</label><select id="p-ad" className="input" value={profile.adId} onChange={(e) => setProfile({ ...profile, adId: e.target.value })}><option value="unknown">Not sure</option><option value="off">Off / deleted</option><option value="on">On</option></select></div>
                </div>
                <div><button className="btn" type="button" onClick={() => act(() => api("PUT", `/api/evidence/devices/${phone}/profile`, profile), "Saved; its CVEs are matched from now on.")}>Save profile</button></div>
              </>
            )}
          </section>
        </div>
      </div>
    </div>
  );
}
