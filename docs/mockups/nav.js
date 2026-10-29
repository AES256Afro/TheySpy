// Shared shell for the mockups: applies the saved look and branding, then renders the sidebar
// into <aside class="side" data-on="...">. Preferences live in this browser only (like BoxPilot).
const TS_LOOKS = [
  { id: 'auto', name: 'Per screen', desc: 'Each screen keeps the look it was designed in.' },
  { id: 'ops', name: 'Ops', desc: 'Dark navy, cyan accents. Mockups 1–3, 5.' },
  { id: 'light', name: 'Daylight', desc: 'Clean and bright. Mockups 6, 7.' },
  { id: 'pihole', name: 'Sentinel', desc: 'Deep green, Pi-hole lime. Mockup 4.' },
  { id: 'evidence', name: 'Evidence', desc: 'Charcoal and amber, forensic. Mockup 8.' },
  { id: 'paper', name: 'Briefing', desc: 'Editorial paper and serif. Mockup 9.' },
  { id: 'glass', name: 'Glass', desc: 'Frosted panels over a gradient. Mockup 10.' },
];
const TS_SCREENS = [
  ['01-command-center', 'overview', '◎', 'Overview'],
  ['02-fleet', 'fleet', '▦', 'Fleet'],
  ['03-targeted-check', 'search', '⌕', 'Targeted check'],
  ['04-pihole-sentinel', 'pihole', '◍', 'Pi-hole Sentinel'],
  ['05-vuln-intel', 'intel', '⚠', 'CVEs & zero-days'],
  ['06-this-device', 'device', '▭', 'This device'],
  ['07-exposure', 'exposure', '◐', 'Ad exposure'],
  ['12-baselines', 'baselines', '▚', 'Baselines'],
  ['11-blocklists', 'blocklists', '☰', 'Blocklist library'],
  ['08-evidence-locker', 'evidence', '▤', 'Evidence locker'],
  ['09-weekly-briefing', 'briefing', '¶', 'Briefing'],
  ['10-in-boxpilot', 'boxpilot', '▣', 'In BoxPilot'],
  ['13-appearance', 'appearance', '✎', 'Appearance'],
];
const TS_DEFAULTS = { look: 'auto', accent: '', name: 'TheySpy', glyph: '◉', tagline: '', density: 'comfortable', home: '01-command-center' };

function tsPrefs() {
  try { return { ...TS_DEFAULTS, ...JSON.parse(localStorage.getItem('theyspy.appearance') || '{}') }; }
  catch { return { ...TS_DEFAULTS }; }
}
function tsSavePrefs(p) {
  try { localStorage.setItem('theyspy.appearance', JSON.stringify(p)); } catch { /* private window: applies to this page only */ }
}

function tsApply(p = tsPrefs()) {
  const b = document.body;
  // Remember the look the page was designed in, so "Per screen" can restore it.
  if (b.dataset.designLook === undefined) b.dataset.designLook = [...b.classList].find(c => c.startsWith('t-')) || '';
  if (b.dataset.fixedLook === undefined) {
    [...b.classList].filter(c => c.startsWith('t-')).forEach(c => b.classList.remove(c));
    const cls = p.look === 'auto' ? b.dataset.designLook : `t-${p.look}`;
    if (cls) b.classList.add(cls);
  }
  if (p.accent) b.style.setProperty('--accent', p.accent); else b.style.removeProperty('--accent');
  b.classList.toggle('dense', p.density === 'compact');
  document.querySelectorAll('[data-brand-name]').forEach(e => { e.textContent = p.name || TS_DEFAULTS.name; });
  document.querySelectorAll('[data-brand-glyph]').forEach(e => { e.textContent = p.glyph || TS_DEFAULTS.glyph; });
  document.title = document.title.replace(/^[^·]+·/, `${p.name || TS_DEFAULTS.name} ·`);
}

(() => {
  const p = tsPrefs();
  const side = document.querySelector('aside.side');
  if (side) {
    const on = side.dataset.on;
    const link = ([file, id, icon, label]) => `<a href="${file}.html" class="${id === on ? 'on' : ''}"><span>${icon}</span>${label}</a>`;
    side.innerHTML =
      `<a class="brand" href="${p.home}.html" style="color:var(--text)"><span class="eye" data-brand-glyph></span><span><span data-brand-name></span>` +
      (p.tagline ? `<span class="tagline"></span>` : '') + `</span></a>` +
      '<div class="sep">Watch</div>' + TS_SCREENS.slice(0, 6).map(link).join('') +
      '<div class="sep">Protect</div>' + TS_SCREENS.slice(6, 11).map(link).join('') +
      '<div class="sep">System</div>' + TS_SCREENS.slice(11).map(link).join('') +
      `<div class="foot">IOC set: zero-breach 2026.10.21<br>Feeds synced 4 min ago<br><a href="index.html">← All mockups</a></div>`;
    const tl = side.querySelector('.tagline');
    if (tl) tl.textContent = p.tagline;
  }
  tsApply(p);
})();
