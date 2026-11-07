import { useCallback, useEffect, useState } from "react";
import { api } from "../api.ts";

type Section = { title: string; tone: "good" | "warn" | "bad"; screen: string; lines: string[] };
type Alert = { key: string; at: string; kind: string; priority: string; title: string; message: string; link: string | null; delivered: boolean; error: string | null };
type Token = { id: number; name: string; createdAt: string; lastUsedAt: string | null; revoked: boolean };
type Data = {
  digest: { week: string; since: string; until: string; sections: Section[]; alerts: number };
  alerts: Alert[];
  ntfy: { url: string; topic: string; hasToken: boolean; fromEnv: { url: boolean; topic: boolean; token: boolean }; ready: boolean };
  webhook: { url: string; hasSecret: boolean; ready: boolean };
  tokens: Token[];
};

const toneBadge = { good: "b-ok", warn: "b-med", bad: "b-crit" } as const;
const toneWord = { good: "fine", warn: "look", bad: "act" } as const;
const when = (iso: string) => new Date(iso).toLocaleString();

export function BriefingScreen() {
  const [data, setData] = useState<Data | null>(null);
  const [days, setDays] = useState(7);
  const [ntfy, setNtfy] = useState({ url: "", topic: "", token: "" });
  const [hook, setHook] = useState({ url: "", secret: "" });
  const [newToken, setNewToken] = useState<{ name: string; token: string } | null>(null);
  const [tokenName, setTokenName] = useState("");
  const [message, setMessage] = useState<{ tone: "good" | "bad"; text: string } | null>(null);

  const load = useCallback(async () => {
    const d = await api<Data>("GET", `/api/briefing?days=${days}`);
    setData(d);
    setNtfy((n) => ({ ...n, url: n.url || d.ntfy.url, topic: n.topic || d.ntfy.topic }));
    setHook((h) => ({ ...h, url: h.url || d.webhook.url }));
  }, [days]);
  useEffect(() => { load().catch((e: Error) => setMessage({ tone: "bad", text: e.message })); }, [load]);
  const act = async (fn: () => Promise<unknown>, done: string) => {
    try { await fn(); setMessage({ tone: "good", text: done }); await load(); } catch (e) { setMessage({ tone: "bad", text: e instanceof Error ? e.message : String(e) }); }
  };

  if (!data) return <div className="stack"><h1>Briefing</h1>{message ? <div className="banner bad">{message.text}</div> : <p className="muted small">Loading…</p>}</div>;
  const origin = window.location.origin;
  return (
    <div className="stack">
      <div className="top">
        <div><h1>Briefing</h1><p className="muted small">{days === 7 ? `The week to ${when(data.digest.until)} (${data.digest.week})` : "The last 24 hours"}. Sent to ntfy or your webhook on Monday mornings.</p></div>
        <div className="grow" />
        <div className="seg" role="group" aria-label="Period">{[[1, "24 hours"], [7, "Week"]].map(([d, label]) => <button key={d} type="button" aria-pressed={days === d} onClick={() => setDays(Number(d))}>{label}</button>)}</div>
        <button className="btn" type="button" onClick={() => window.print()}>Print</button>
        <button className="btn primary" type="button" disabled={!data.ntfy.ready && !data.webhook.ready} title={data.ntfy.ready || data.webhook.ready ? "" : "Set up ntfy or a webhook below first"} onClick={() => act(() => api("POST", "/api/briefing/send"), "Sent.")}>Send now</button>
      </div>
      {message && <div className={`banner ${message.tone}`} role="status"><span className="small">{message.text}</span></div>}

      <div className="stack">{data.digest.sections.map((s) => (
        <section key={s.title} className="card stack" style={{ gap: 6 }}>
          <header><h2>{s.title}</h2><span className={`badge ${toneBadge[s.tone]}`}>{toneWord[s.tone]}</span></header>
          {s.lines.map((l) => <p key={l} className="small">{l}</p>)}
          <a className="small" href={s.screen}>Open</a>
        </section>
      ))}</div>

      <div className="two-col">
        <section className="card stack">
          <header><h2>Recent alerts</h2><span className="muted small">each sent once</span></header>
          {data.alerts.length === 0 ? <p className="small muted">No alerts yet. You will hear about new devices, lookups of spyware addresses, exploited bugs in software you run, Pi-hole going quiet, and held blocklist updates.</p> : (
            <div className="list small">{data.alerts.map((a) => (
              <div key={a.key} style={{ alignItems: "flex-start" }}>
                <span className={`badge ${a.priority === "urgent" ? "b-crit" : a.priority === "high" ? "b-high" : "b-info"}`}>{a.kind.replace("_", " ")}</span>
                <span className="grow"><b>{a.title}</b><br /><span className="muted">{a.message}</span></span>
                <span className="muted" title={a.error ?? ""}>{when(a.at)}{a.delivered ? "" : " · not delivered"}</span>
              </div>
            ))}</div>
          )}
        </section>

        <div className="stack sticky">
          <section className="card stack">
            <h3>Where alerts go (ntfy)</h3>
            <p className="small muted">An ntfy server and topic: your own (BoxPilot’s ntfy app) or ntfy.sh. Subscribe to the topic in the ntfy app on your phone.</p>
            <div className="compact-fields">
              <div className="field"><label htmlFor="n-url">Server</label><input id="n-url" className="input" placeholder="https://ntfy.sh" value={ntfy.url} disabled={data.ntfy.fromEnv.url} onChange={(e) => setNtfy({ ...ntfy, url: e.target.value })} /></div>
              <div className="field"><label htmlFor="n-topic">Topic</label><input id="n-topic" className="input" placeholder="theyspy-alerts" value={ntfy.topic} disabled={data.ntfy.fromEnv.topic} onChange={(e) => setNtfy({ ...ntfy, topic: e.target.value })} /></div>
              <div className="field"><label htmlFor="n-token">Token</label><input id="n-token" className="input" type="password" placeholder={data.ntfy.hasToken ? "saved; type to replace" : "optional"} value={ntfy.token} disabled={data.ntfy.fromEnv.token} onChange={(e) => setNtfy({ ...ntfy, token: e.target.value })} /></div>
            </div>
            <div className="row">
              <button className="btn" type="button" onClick={() => act(() => api("PUT", "/api/briefing/ntfy", { url: ntfy.url, topic: ntfy.topic, ...(ntfy.token ? { token: ntfy.token } : {}) }), "Saved.")}>Save</button>
              <button className="btn" type="button" disabled={!data.ntfy.ready} onClick={() => act(() => api("POST", "/api/briefing/ntfy/test"), "Test notification sent.")}>Send a test</button>
            </div>
          </section>

          <section className="card stack">
            <h3>Or a webhook</h3>
            <p className="small muted">Each alert and the weekly briefing POSTed as JSON to an address of yours: a Discord or Slack relay, Home Assistant, n8n. With a secret set, the <code>X-TheySpy-Signature</code> header carries the HMAC-SHA256 of the body.</p>
            <div className="compact-fields">
              <div className="field"><label htmlFor="w-url">Address</label><input id="w-url" className="input" placeholder="https://hooks.example/theyspy" value={hook.url} onChange={(e) => setHook({ ...hook, url: e.target.value })} /></div>
              <div className="field"><label htmlFor="w-secret">Secret</label><input id="w-secret" className="input" type="password" autoComplete="off" placeholder={data.webhook.hasSecret ? "saved; type to replace" : "optional"} value={hook.secret} onChange={(e) => setHook({ ...hook, secret: e.target.value })} /></div>
            </div>
            <div className="row">
              <button className="btn" type="button" onClick={() => act(async () => { await api("PUT", "/api/briefing/webhook", { url: hook.url, ...(hook.secret ? { secret: hook.secret } : {}) }); setHook((h) => ({ ...h, secret: "" })); }, "Saved.")}>Save</button>
              <button className="btn" type="button" disabled={!data.webhook.ready} onClick={() => act(() => api("POST", "/api/briefing/webhook/test"), "Test notification sent.")}>Send a test</button>
            </div>
          </section>

          <section className="card stack">
            <h3>API and MCP</h3>
            <p className="small muted">Read-only access for other tools: BoxPilot’s agents, Claude, or any MCP client. Each token is shown once.</p>
            {newToken && (
              <div className="banner good stack" style={{ gap: 6 }}>
                <span className="small">Token for <b>{newToken.name}</b>, copy it now:</span>
                <code className="small">{newToken.token}</code>
                <span className="small">MCP server: <code>{origin}/mcp</code> with header <code>Authorization: Bearer …</code>. JSON API: <code>{origin}/api/v1/devices</code>.</span>
              </div>
            )}
            <div className="row">
              <input className="input grow" placeholder="What will use it, e.g. BoxPilot agents" value={tokenName} onChange={(e) => setTokenName(e.target.value)} aria-label="Token name" />
              <button className="btn" type="button" disabled={!tokenName.trim()} onClick={() => act(async () => { setNewToken(await api<{ name: string; token: string }>("POST", "/api/briefing/tokens", { name: tokenName })); setTokenName(""); }, "Token created.")}>Create</button>
            </div>
            <div className="list small">{data.tokens.filter((t) => !t.revoked).map((t) => (
              <div key={t.id}><span className="grow">{t.name}<br /><span className="muted">{t.lastUsedAt ? `used ${when(t.lastUsedAt)}` : "not used yet"}</span></span>
                <button className="btn small danger" type="button" onClick={() => act(() => api("DELETE", `/api/briefing/tokens/${t.id}`), "Revoked.")}>Revoke</button></div>
            ))}</div>
          </section>
        </div>
      </div>
    </div>
  );
}
