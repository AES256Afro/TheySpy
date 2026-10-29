import { useCallback, useEffect, useMemo, useState } from "react";
import { useNames } from "../names.ts";
import { api, lastLogLine, waitForJob, type Job } from "../api.ts";

type Baseline = { id: string; name: string; severity: number; categories: string[]; lists: string[]; summary: string; custom?: boolean };
type Category = { id: string; group: string; name: string };
type Device = { ip: string; name: string | null; queries: number; key: string; suggested: string; why: string };
type Assignment = { baseline: string; client: string | null; mode?: "shadow"; startedAt?: string; appliedAt?: string; entries?: number; groupName?: string | null };
type Overview = {
  baselines: Baseline[]; categories: Category[];
  scopes: { network: { key: string; suggested: string; why: string }; devices: Device[] };
  assignments: Record<string, Assignment>;
  pihole: { connected: boolean; api: boolean; write: boolean };
};
type Site = { site: string; names: string[]; more: number; queries: number; today: "blocked" | "partly" | "allowed"; categories: string[]; lists: string[]; kept: boolean; risk: "high" | "medium" | "low" };
type Level = { id: string; name: string; severity: number; summary: string; sites: number; newlyBlocked: number; mightBreak: number; shareAfter: number; details: Site[]; missingLists: string[]; missingCategories: string[] };
type Shadow = { baseline: string; startedAt: string; totalQueries: number; shareNow: number; level: Level };
type Preview = { scope: string; client: string | null; windowDays: number; basis: string; totalQueries: number; shareNow: number; levels: Level[]; exceptions: string[]; shadow: Shadow | null };

const severityTone = ["", "ok", "med", "high", "crit"];
const riskLabel = { high: "Likely to break", medium: "Might break", low: "Unlikely" } as const;
const riskClass = { high: "r-high", medium: "r-med", low: "r-low" } as const;
const todayBadge = { blocked: "b-ok", partly: "b-med", allowed: "b-info" } as const;
const pct = (x: number) => `${(x * 100).toFixed(1)}%`;
const n = (x: number) => x.toLocaleString();

export function BaselinesScreen() {
  const names = useNames();
  const [overview, setOverview] = useState<Overview | null>(null);
  const [preview, setPreview] = useState<Preview | null>(null);
  const [client, setClient] = useState("");
  const [days, setDays] = useState(7);
  const [picked, setPicked] = useState<string | null>(null);
  const [filter, setFilter] = useState<"all" | "new" | "break">("all");
  const [busy, setBusy] = useState("");
  const [loading, setLoading] = useState(false);
  const [message, setMessage] = useState<{ tone: "good" | "bad" | "warn"; text: string } | null>(null);
  const [editing, setEditing] = useState<{ name: string; categories: string[] } | null>(null);

  const load = useCallback(async () => setOverview(await api<Overview>("GET", "/api/blocklists/baselines")), []);
  const loadPreview = useCallback(async () => {
    setLoading(true);
    try {
      const params = new URLSearchParams({ days: String(days), ...(client ? { client } : {}) });
      setPreview(await api<Preview>("GET", `/api/blocklists/baselines/preview?${params}`));
    } finally {
      setLoading(false);
    }
  }, [client, days]);
  useEffect(() => { load().catch((e: Error) => setMessage({ tone: "bad", text: e.message })); }, [load]);
  useEffect(() => {
    if (overview?.pihole.connected) loadPreview().catch((e: Error) => setMessage({ tone: "bad", text: e.message }));
  }, [overview?.pihole.connected, loadPreview]);

  const scope = overview && (client ? overview.scopes.devices.find((d) => d.ip === client) : overview.scopes.network);
  const scopeKey = client ? scope?.key ?? "" : "network";
  const assignment = overview?.assignments[scopeKey] ?? null;
  const applied = assignment && assignment.mode !== "shadow" ? assignment : null;
  const shadow = assignment?.mode === "shadow" ? assignment : null;
  const selected = picked ?? assignment?.baseline ?? scope?.suggested ?? "balanced";
  const level = preview?.levels.find((l) => l.id === selected) ?? null;
  const baseline = overview?.baselines.find((b) => b.id === selected) ?? null;
  const categoryName = useMemo(() => new Map((overview?.categories ?? []).map((c) => [c.id, c.name])), [overview]);
  const rows = (level?.details ?? []).filter((s) => filter === "all" || (filter === "new" ? s.today !== "blocked" && !s.kept : s.risk !== "low" && !s.kept));
  const kept = preview?.exceptions.length ?? 0;
  const scopeLabel = client ? `${names[client]?.name ?? (scope && "name" in scope && scope.name) ?? client} (${client})` : "the whole network";

  const run = async (label: string, start: () => Promise<{ job: Job }>) => {
    setBusy(label);
    setMessage(null);
    try {
      const done = await waitForJob((await start()).job.id);
      setMessage({ tone: done.status === "succeeded" ? "good" : "bad", text: lastLogLine(done) || done.status });
      setPicked(null);
      await load();
      await loadPreview();
    } catch (error) {
      setMessage({ tone: "bad", text: error instanceof Error ? error.message : String(error) });
    } finally {
      setBusy("");
    }
  };
  const act = async (fn: () => Promise<unknown>, done: string) => {
    setMessage(null);
    try {
      await fn();
      setMessage({ tone: "good", text: done });
      await load();
      await loadPreview();
    } catch (error) {
      setMessage({ tone: "bad", text: error instanceof Error ? error.message : String(error) });
    }
  };
  const nameOf = (id: string) => overview?.baselines.find((b) => b.id === id)?.name ?? id;
  const keep = async (site: Site, value: boolean) => {
    try {
      await api("PUT", "/api/blocklists/baselines/exceptions", { scope: scopeKey, site: site.site, keep: value });
      await loadPreview();
      if (applied) setMessage({ tone: "warn", text: `Saved. Pi-hole picks the change up at its next gravity update (or apply ${baseline?.name ?? "the baseline"} again now).` });
    } catch (error) {
      setMessage({ tone: "bad", text: error instanceof Error ? error.message : String(error) });
    }
  };

  const header = (
    <div className="top">
      <div><h1>Baselines</h1><p className="muted small">Suggested blocking levels, from the gentlest to the most severe. Pick one to see which sites it would block, based on {days} days of this network’s real DNS traffic.</p></div>
    </div>
  );
  if (!overview) return <div className="stack">{header}{message ? <div className="banner bad">{message.text}</div> : <p className="muted small">Loading…</p>}</div>;
  if (!overview.pihole.connected) {
    return (
      <div className="stack">{header}
        <div className="banner warn"><span className="small">Baselines are worked out from Pi-hole’s query history. Connect Pi-hole on the <a href="/pihole">Pi-hole Sentinel</a> screen first.</span></div>
        <div className="tiers">{overview.baselines.map((b) => <section key={b.id} className="tier"><h2>{b.name}</h2><Severity level={b.severity} /><p className="sum">{b.summary}</p></section>)}</div>
      </div>
    );
  }

  return (
    <div className="stack">
      {header}
      <div className="row">
        <label className="small muted" htmlFor="baseline-scope">Apply to</label>
        <select id="baseline-scope" className="input" style={{ maxWidth: 320 }} value={client} onChange={(e) => { setClient(e.target.value); setPicked(null); setFilter("all"); }}>
          <option value="">Whole network{assignedLabel(overview.assignments.network)}</option>
          {overview.scopes.devices.map((d) => <option key={d.ip} value={d.ip}>{names[d.ip]?.name ?? d.name ?? d.ip}{(names[d.ip]?.name ?? d.name) ? ` (${d.ip})` : ""} · {n(d.queries)} lookups{assignedLabel(overview.assignments[d.key])}</option>)}
        </select>
        <span className="small muted">Traffic from</span>
        <div className="seg" role="group" aria-label="Traffic window">{[1, 7, 14, 30].map((d) => <button key={d} type="button" aria-pressed={days === d} onClick={() => setDays(d)}>{d === 1 ? "24 hours" : `${d} days`}</button>)}</div>
        {loading && <span className="small muted">Reading Pi-hole…</span>}
      </div>
      {message && <div className={`banner ${message.tone}`} role="status"><span className="small">{message.text}</span></div>}

      <div className="tiers" role="group" aria-label="Baselines">
        {overview.baselines.map((b) => {
          const l = preview?.levels.find((x) => x.id === b.id);
          return (
            <button key={b.id} type="button" className="tier" aria-pressed={selected === b.id} onClick={() => { setPicked(b.id); setFilter("all"); }}>
              <span className="tags">
                {scope?.suggested === b.id && <span className="badge b-info">suggested</span>}
                {applied?.baseline === b.id && <span className="badge b-ok">applied</span>}
                {shadow?.baseline === b.id && <span className="badge b-med">in shadow</span>}
              </span>
              <h2>{b.name}</h2>
              <Severity level={b.severity} />
              <span className="sum">{b.summary}</span>
              <span className="nums">
                <span><b>{l ? n(l.sites) : "—"}</b>sites</span>
                <span><b>{l ? n(l.newlyBlocked) : "—"}</b>newly blocked</span>
                <span><b className={l?.mightBreak ? "r-med" : undefined}>{l ? n(l.mightBreak) : "—"}</b>might break</span>
              </span>
            </button>
          );
        })}
        {!overview.baselines.some((b) => b.custom) && (
          <button type="button" className="tier add" onClick={() => setEditing({ name: "", categories: ["spyware", "malware", "phishing"] })}>
            <h2>Your own level</h2>
            <span className="sum">Pick the categories yourself, for a device none of the four suits.</span>
          </button>
        )}
      </div>

      {(editing || selected === "custom") && (
        <CustomEditor key={overview.baselines.some((b) => b.custom) ? "edit" : "new"}
          categories={overview.categories}
          initial={editing ?? (() => { const c = overview.baselines.find((b) => b.custom); return { name: c?.name ?? "", categories: c?.categories ?? [] }; })()}
          exists={overview.baselines.some((b) => b.custom)}
          onSave={(value) => act(async () => { await api("PUT", "/api/blocklists/baselines/custom", value); setEditing(null); setPicked("custom"); }, "Saved your level.")}
          onDelete={() => act(async () => { await api("DELETE", "/api/blocklists/baselines/custom"); setPicked(null); setEditing(null); }, "Deleted your level.")}
          onCancel={editing ? () => setEditing(null) : undefined}
        />
      )}

      {preview?.shadow && (
        <section className="card stack" style={{ borderColor: "var(--med)" }}>
          <header>
            <h2>{nameOf(preview.shadow.baseline)} in shadow since {new Date(preview.shadow.startedAt).toLocaleString()}</h2>
            <span className="badge b-med">nothing blocked</span>
          </header>
          <p className="small">{preview.shadow.totalQueries
            ? <>Of {n(preview.shadow.totalQueries)} lookups since then, {nameOf(preview.shadow.baseline)} would have blocked {pct(preview.shadow.level.shareAfter)} (Pi-hole blocked {pct(preview.shadow.shareNow)}): {n(preview.shadow.level.sites)} sites, {n(preview.shadow.level.mightBreak)} that might break something.</>
            : "No lookups counted yet. The live watch counts this scope’s new lookups every 30 seconds."}</p>
          {preview.shadow.level.details.length > 0 && <SiteTable rows={preview.shadow.level.details} categoryName={categoryName} onKeep={keep} />}
        </section>
      )}

      <div className="two-col">
        <section className="card">
          <header>
            <h2>Sites {level?.name ?? "this level"} would block for {scopeLabel}</h2>
            <div className="seg" role="group" aria-label="Filter sites">
              {([["all", "All"], ["new", "Newly blocked"], ["break", "Might break"]] as const).map(([id, label]) => <button key={id} type="button" aria-pressed={filter === id} onClick={() => setFilter(id)}>{label}</button>)}
            </div>
          </header>
          {level && level.missingLists.length > 0 && (
            <div className="banner warn" style={{ marginBottom: 12 }}><span className="small">{level.name} uses {level.missingLists.length} list{level.missingLists.length === 1 ? "" : "s"} that {level.missingLists.length === 1 ? "is" : "are"} not on yet, so this preview shows less than it will block. Applying it turns {level.missingLists.length === 1 ? "it" : "them"} on and fetches {level.missingLists.length === 1 ? "it" : "them"} first.</span></div>
          )}
          {level && level.missingCategories.length > 0 && (
            <div className="banner warn" style={{ marginBottom: 12 }}><span className="small">No list that is on covers {level.missingCategories.map((c) => categoryName.get(c) ?? c).join(", ")}, so {level.name} blocks nothing there yet. Turn one on in the <a href="/blocklists">Blocklist library</a>.</span></div>
          )}
          {!preview ? <p className="small muted">Reading Pi-hole’s history…</p> : rows.length === 0 ? <p className="small muted">{filter === "all" ? "Nothing in this traffic window would be blocked at this level." : "None."}</p> : <SiteTable rows={rows} categoryName={categoryName} onKeep={keep} />}
          <p className="small muted" style={{ marginTop: 10 }}>Grouped by site. Based on {preview?.basis ?? "Pi-hole’s history"}. Connectivity checks, certificate checks, time servers and the sites your network uses most are never blocked by any baseline. Spyware, malware and phishing names are shown defanged.</p>
        </section>

        <div className="stack sticky">
          <section className="card stack">
            <h3>Impact</h3>
            <div className="before-after">
              <div><span className="small muted">Blocked now</span><b>{preview ? pct(preview.shareNow) : "—"}</b></div>
              <div><span className="small muted">With {level?.name ?? "it"}</span><b>{level ? pct(level.shareAfter) : "—"}</b></div>
            </div>
            <div className="list small">
              <div><span className="grow">Lookups in the window</span><b>{preview ? n(preview.totalQueries) : "—"}</b></div>
              <div><span className="grow">Sites newly blocked</span><b>{level ? n(level.newlyBlocked) : "—"}</b></div>
              <div><span className="grow">Might break something</span><b>{level ? n(level.mightBreak) : "—"}</b></div>
              <div><span className="grow">Kept allowing (exceptions)</span><b>{kept}</b></div>
            </div>
          </section>
          {scope && (
            <section className="card stack">
              <h3>Why {overview.baselines.find((b) => b.id === scope.suggested)?.name} is suggested</h3>
              <p className="small">{scope.why}</p>
            </section>
          )}
          <section className="card stack">
            <h3>{applied ? `Applied: ${nameOf(applied.baseline)}` : shadow ? `In shadow: ${nameOf(shadow.baseline)}` : "Apply"}</h3>
            {applied && <p className="small muted">Since {new Date(applied.appliedAt ?? "").toLocaleString()} · {n(applied.entries ?? 0)} entries in Pi-hole{applied.groupName ? ` · group “${applied.groupName}”` : ""}</p>}
            <div className="row">
              {!overview.pihole.api ? <p className="small muted">Applying needs Pi-hole’s API; TheySpy is reading its database file.</p>
                : !overview.pihole.write ? <p className="small muted">Allow TheySpy to change Pi-hole on the <a href="/pihole">Pi-hole Sentinel</a> screen to apply baselines from here.</p>
                : applied?.baseline !== selected && (
                  <button className="btn primary" type="button" disabled={Boolean(busy)} onClick={() => run("apply", () => api("POST", "/api/blocklists/baselines/apply", { baselineId: selected, client: client || undefined }))}>
                    {busy === "apply" ? "Applying…" : `${applied ? "Switch to" : shadow?.baseline === selected ? "Apply for real:" : "Apply"} ${baseline?.name ?? ""}`}
                  </button>
                )}
              {!applied && shadow?.baseline !== selected && (
                <button className="btn" type="button" disabled={Boolean(busy)} onClick={() => act(() => api("POST", "/api/blocklists/baselines/shadow", { baselineId: selected, client: client || undefined }), `Trying ${baseline?.name ?? "it"} in shadow: nothing is blocked; new lookups are counted against it.`)}>
                  Try {baseline?.name ?? ""} in shadow
                </button>
              )}
              {shadow && <button className="btn" type="button" disabled={Boolean(busy)} onClick={() => act(() => api("DELETE", "/api/blocklists/baselines/shadow", { client: client || undefined }), "Stopped the shadow.")}>Stop shadow</button>}
              {applied && overview.pihole.write && (
                <button className="btn" type="button" disabled={Boolean(busy)} onClick={() => run("remove", () => api("POST", "/api/blocklists/baselines/remove", { client: client || undefined }))}>
                  {busy === "remove" ? "Removing…" : "Remove baseline"}
                </button>
              )}
            </div>
            <p className="small muted">{client
              ? "Creates a Pi-hole group for this device, adds the device to it (keeping its other groups) and subscribes that group to the baseline’s list. Remove puts Pi-hole back exactly as it was."
              : "Subscribes Pi-hole’s Default group to the baseline’s list, so it applies to every device. Remove takes it out again."} Shadow changes nothing in Pi-hole: it counts new lookups and shows what the level would have blocked.</p>
          </section>
        </div>
      </div>
    </div>
  );
}

function Severity({ level }: { level: number }) {
  return <span className="lvl" aria-label={`Severity ${level} of 4`}>{[1, 2, 3, 4].map((i) => <i key={i} style={i <= level ? { background: `var(--${severityTone[level]})` } : undefined} />)}</span>;
}

// Spyware, malware and phishing sites are not offered as exceptions; a wrongly listed name belongs
// in the library's never-block pins, where every list respects it.
const securityCategories = new Set(["spyware", "malware", "phishing", "cryptomining"]);

const assignedLabel = (a?: Assignment) => (a ? ` · ${a.baseline}${a.mode === "shadow" ? " (shadow)" : ""}` : "");

function SiteTable({ rows, categoryName, onKeep }: { rows: Site[]; categoryName: Map<string, string>; onKeep: (site: Site, keep: boolean) => void }) {
  return (
    <div className="table-wrap"><table>
      <thead><tr><th>Site</th><th>Category</th><th>Lookups</th><th>Breakage</th><th>Today</th><th></th></tr></thead>
      <tbody>{rows.map((s) => (
        <tr key={s.site} className={s.kept ? "kept" : undefined}>
          <td className="site"><b className="mono">{s.site}</b><div className="sub">{s.names.filter((x) => x !== s.site).join(", ")}{s.more ? ` and ${s.more} more` : ""}</div>{s.lists.length > 0 && <div className="sub">{s.lists.join(" · ")}</div>}</td>
          <td className="small">{s.categories.map((c) => categoryName.get(c) ?? c).join(", ")}</td>
          <td className="mono">{n(s.queries)}</td>
          <td><span className={`risk ${riskClass[s.risk]}`}>{riskLabel[s.risk]}</span></td>
          <td><span className={`badge ${todayBadge[s.today]}`}>{s.today}</span></td>
          <td>{s.kept
            ? <button className="btn small" type="button" onClick={() => onKeep(s, false)}>Block it</button>
            : !s.categories.some((c) => securityCategories.has(c)) && <button className="btn small" type="button" onClick={() => onKeep(s, true)}>Keep allowing</button>}</td>
        </tr>
      ))}</tbody>
    </table></div>
  );
}

function CustomEditor({ categories, initial, exists, onSave, onDelete, onCancel }: {
  categories: Category[]; initial: { name: string; categories: string[] }; exists: boolean;
  onSave: (value: { name: string; categories: string[] }) => void; onDelete: () => void; onCancel?: () => void;
}) {
  const [name, setName] = useState(initial.name);
  const [chosen, setChosen] = useState<string[]>(initial.categories);
  const groups = [...new Set(categories.map((c) => c.group))];
  return (
    <section className="card stack">
      <header><h2>{exists ? "Your level" : "Make your own level"}</h2></header>
      <div className="field"><label htmlFor="custom-name">Name</label><input id="custom-name" className="input" style={{ maxWidth: 280 }} maxLength={40} placeholder="Custom" value={name} onChange={(e) => setName(e.target.value)} /></div>
      {groups.map((g) => (
        <div key={g} className="field">
          <span className="label">{g[0].toUpperCase() + g.slice(1)}</span>
          <div className="row" role="group" aria-label={`${g} categories`}>{categories.filter((c) => c.group === g).map((c) => (
            <label key={c.id} className="small row" style={{ gap: 4 }}>
              <input type="checkbox" checked={c.id === "spyware" || chosen.includes(c.id)} disabled={c.id === "spyware"} onChange={(e) => setChosen(e.target.checked ? [...chosen, c.id] : chosen.filter((x) => x !== c.id))} />{c.name}
            </label>
          ))}</div>
        </div>
      ))}
      <p className="small muted">Spyware & ADINT is part of every level. A category blocks only what the lists you have turned on cover.</p>
      <div className="row">
        <button className="btn primary" type="button" onClick={() => onSave({ name, categories: chosen })}>Save</button>
        {onCancel && <button className="btn" type="button" onClick={onCancel}>Cancel</button>}
        {exists && <button className="btn danger" type="button" onClick={onDelete}>Delete</button>}
      </div>
    </section>
  );
}
