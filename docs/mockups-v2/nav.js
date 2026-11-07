// The shared sidebar for the round-two mock-ups: five places and "More", with live counts. Each
// page says which place is on and may pass its own sidebar; otherwise this one is drawn.
(() => {
  const side = document.querySelector("aside.side[data-on]");
  if (!side || side.children.length) return;
  const on = side.dataset.on;
  const places = [
    ["home", "◎", "Home", ""], ["devices", "▦", "Devices", "<span class='n bad'>1</span>"], ["dns", "◍", "DNS watch", ""],
    ["intel", "⚠", "Exploited bugs", "<span class='n warn'>4</span>"], ["evidence", "▤", "Evidence", ""],
  ];
  const more = [["lists", "☰", "Blocklists &amp; baselines"], ["check", "⌕", "Check one thing"], ["briefing", "¶", "Briefing &amp; alerts"], ["sites", "◇", "Other sites"], ["settings", "✎", "Settings"]];
  side.innerHTML = `<a class="brand" href="A-verdict-first.html"><span class="glyph">◉</span><span>TheySpy</span></a>` +
    places.map(([id, i, l, n]) => `<a class="${id === on ? "on" : ""}"><span>${i}</span>${l}${n}</a>`).join("") +
    `<div class="sep">More</div>` + more.map(([id, i, l]) => `<a class="more-only ${id === on ? "on" : ""}"><span>${i}</span>${l}</a>`).join("") +
    `<div class="foot"><span><span class="dot ok"></span> Pi-hole · watching</span><span>Indicators 2026-10-16 · 405</span><span>Version 1.10.0</span></div>`;
})();
