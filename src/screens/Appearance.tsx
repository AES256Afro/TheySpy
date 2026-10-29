import { useEffect, useState } from "react";
import { contrast, over } from "../../shared/contrast.mjs";
import { accentPresets, appearanceDefaults, glyphs, lookById, lookPreviewStyle, looks, resolveLook, type Appearance } from "../looks/looks.ts";
import { Link } from "../router.tsx";
import { screens } from "../screens.ts";

export type AppearanceControls = {
  appearance: Appearance;
  server: Partial<Appearance>;
  local: Partial<Appearance>;
  setLocal: (next: Partial<Appearance>) => void;
  setPreview: (preview: Partial<Appearance> | null) => void;
  saveForEveryone: (value: Partial<Appearance>) => Promise<void>;
  resetForEveryone: () => Promise<void>;
};

type Scope = "browser" | "everyone";
const fieldLabels: Record<keyof Appearance, string> = { look: "look", name: "name", tagline: "tagline", glyph: "logo", accent: "accent", home: "home screen", density: "density" };

function LookCard({ id, name, description, pressed, onPick }: { id: string; name: string; description: string; pressed: boolean; onPick: () => void }) {
  const preview = id === "auto" ? (
    <div className="mini-auto" aria-hidden="true">
      {["ops", "light", "paper"].map((lookId) => <div key={lookId} style={lookPreviewStyle(lookById(lookId))} />)}
    </div>
  ) : (
    <div className="mini" style={lookPreviewStyle(lookById(id))} aria-hidden="true">
      <div className="ms"><i /><i /><i /><i /></div>
      <div className="mb"><div className="mc"><u /><s /></div><div className="mc"><u /><s className="c" /></div><div className="mc"><u /><u /></div><div className="mc"><u /><s /></div></div>
    </div>
  );
  return (
    <button type="button" className="look-card" aria-pressed={pressed} onClick={onPick}>
      {preview}
      <div className="cap"><b>{name}</b>{description}</div>
    </button>
  );
}

export function AppearanceScreen({ appearance, server, local, setLocal, setPreview, saveForEveryone, resetForEveryone }: AppearanceControls) {
  const [scope, setScope] = useState<Scope>("browser");
  const [draft, setDraft] = useState<Partial<Appearance>>({});
  const [status, setStatus] = useState("");

  // Editing the defaults for everyone previews the draft live; leaving the page drops the preview.
  useEffect(() => {
    setPreview(scope === "everyone" ? draft : null);
  }, [scope, draft, setPreview]);
  useEffect(() => () => setPreview(null), [setPreview]);

  const shown: Appearance = scope === "browser" ? appearance : { ...appearanceDefaults, ...server, ...draft };
  const change = (key: keyof Appearance, value: string) => {
    setStatus("");
    if (scope === "browser") setLocal({ ...local, [key]: value });
    else setDraft({ ...draft, [key]: value });
  };

  const save = async () => {
    try {
      await saveForEveryone({ ...server, ...draft });
      setDraft({});
      setStatus("Saved as the default for everyone.");
    } catch (failure) {
      setStatus(failure instanceof Error ? failure.message : "Could not save.");
    }
  };

  const overridden = (Object.keys(local) as (keyof Appearance)[]).filter((key) => key in fieldLabels);
  const lookForContrast = resolveLook(shown.look, "ops");
  const accentRatio = shown.accent ? contrast(shown.accent, over(lookForContrast.tokens.panel, lookForContrast.tokens.bg)) : null;

  return (
    <div className="stack">
      <div className="top">
        <div><h1>Appearance &amp; branding</h1><p className="muted small">Every mockup’s style is a look. Pick one for the whole app, then make it yours.</p></div>
        <div className="grow" />
        <div className="seg" role="group" aria-label="Apply changes to">
          <button type="button" aria-pressed={scope === "browser"} onClick={() => { setScope("browser"); setDraft({}); }}>This browser</button>
          <button type="button" aria-pressed={scope === "everyone"} onClick={() => setScope("everyone")}>Default for everyone</button>
        </div>
      </div>

      {scope === "browser" ? (
        <div className="banner">
          <span className="small grow">Changes apply at once and stay in this browser only, so a phone and a wall screen can differ.
            {overridden.length > 0 && <> This browser overrides: {overridden.map((key) => fieldLabels[key]).join(", ")}.</>}</span>
          {overridden.length > 0 && <button className="btn small" type="button" onClick={() => setLocal({})}>Use the defaults</button>}
        </div>
      ) : (
        <div className="banner warn">
          <span className="small grow">You are editing the default every browser starts from (this browser’s own overrides are paused while you edit). <code>TS_LOOK</code>, <code>TS_BRAND_*</code> and <code>TS_ACCENT</code> set the starting point; what you save here wins over them.</span>
          <button className="btn small" type="button" onClick={() => { void resetForEveryone(); setDraft({}); }}>Back to environment defaults</button>
          <button className="btn small primary" type="button" onClick={save} disabled={Object.keys(draft).length === 0}>Save for everyone</button>
        </div>
      )}
      {status && <p className="small" role="status">{status}</p>}

      <div className="two-col">
        <div className="stack">
          <section className="card">
            <header><h2>Look</h2><span className="muted small">Restyles every screen</span></header>
            <div className="looks">
              <LookCard id="auto" name="Per screen" description="Each screen keeps the look it was designed in." pressed={shown.look === "auto"} onPick={() => change("look", "auto")} />
              {looks.map((look) => <LookCard key={look.id} id={look.id} name={look.name} description={look.description} pressed={shown.look === look.id} onPick={() => change("look", look.id)} />)}
            </div>
          </section>

          <section className="card">
            <header><h2>Branding</h2></header>
            <div className="field"><label htmlFor="brand-name">Name</label><input id="brand-name" className="input" maxLength={28} value={shown.name} onChange={(e) => change("name", e.target.value || appearanceDefaults.name)} />
              <span className="hint">Shown in the sidebar, page titles and the sign-in page; later in the briefing and notifications.</span></div>
            <div className="field"><label htmlFor="brand-tagline">Tagline</label><input id="brand-tagline" className="input" maxLength={40} placeholder="e.g. Home network watch" value={shown.tagline} onChange={(e) => change("tagline", e.target.value)} /></div>
            <div className="field"><span className="label" id="logo-label">Logo</span>
              <div className="row" role="group" aria-labelledby="logo-label">
                {glyphs.map((glyph) => <button key={glyph} type="button" className="glyph-pick" aria-pressed={shown.glyph === glyph} onClick={() => change("glyph", glyph)}>{glyph}</button>)}
              </div>
              <span className="hint">Uploading your own SVG or PNG arrives with the branding store in M10.</span></div>
            <div className="field"><span className="label" id="accent-label">Accent colour</span>
              <div className="row" role="group" aria-labelledby="accent-label">
                <button type="button" className={`btn small ${shown.accent ? "" : "primary"}`} onClick={() => change("accent", "")}>Look’s own</button>
                {accentPresets.map((colour) => <button key={colour} type="button" className="swatch" aria-pressed={shown.accent === colour} aria-label={`Accent ${colour}`} style={{ background: colour }} onClick={() => change("accent", colour)} />)}
                <input type="color" className="swatch" aria-label="Custom accent colour" value={shown.accent || lookForContrast.tokens.accent} onChange={(e) => change("accent", e.target.value)} />
              </div>
              {accentRatio !== null && accentRatio < 4.5 && <span className="hint" role="alert"><span className="badge b-high">Low contrast</span> {accentRatio.toFixed(1)}:1 on this look’s panels; links in this colour will be hard to read (needs 4.5:1).</span>}
            </div>
          </section>

          <section className="card">
            <header><h2>Layout</h2></header>
            <div className="field"><label htmlFor="home">Home screen</label>
              <select id="home" className="input" value={shown.home} onChange={(e) => change("home", e.target.value)}>
                {screens.filter((s) => s.id !== "appearance").map((s) => <option key={s.id} value={s.id}>{s.label}</option>)}
              </select>
              <span className="hint">What opens at “/” and where the logo links.</span></div>
            <div className="field"><span className="label" id="density-label">Density</span>
              <div className="seg" role="group" aria-labelledby="density-label">
                {(["comfortable", "compact"] as const).map((density) => <button key={density} type="button" aria-pressed={shown.density === density} onClick={() => change("density", density)}>{density === "comfortable" ? "Comfortable" : "Compact"}</button>)}
              </div></div>
          </section>
        </div>

        <div className="stack sticky">
          <section className="card stack">
            <header><h2>Preview</h2><span className="muted small">{shown.look === "auto" ? "Per screen" : lookById(shown.look).name}</span></header>
            <div className="grid g2">
              <div className="card"><h3>Posture</h3><div className="kpi">64</div></div>
              <div className="card"><h3>IOC hits</h3><div className="kpi crit">3</div></div>
            </div>
            <div className="banner bad"><span className="badge b-crit">IOC</span><span className="small">Kitchen phone looked up <code>noas-edge[.]example</code></span></div>
            <div className="row"><span className="badge b-crit">0-DAY</span><span className="badge b-high">KEV</span><span className="badge b-med">medium</span><span className="badge b-ok">clean</span><span className="badge b-info">new</span></div>
            <div className="row"><button className="btn primary" type="button">Primary</button><button className="btn" type="button">Secondary</button><button className="btn danger" type="button">Block</button></div>
            <p className="small">A <Link href="/activity">link in the accent colour</Link> next to <span className="muted">muted text</span>.</p>
          </section>
        </div>
      </div>
    </div>
  );
}
