import { lookById, type Appearance } from "../looks/looks.ts";
import { Link } from "../router.tsx";
import type { Screen } from "../screens.ts";

/** A screen whose content arrives in a later milestone. It already wears its look and has its route. */
export function PlaceholderScreen({ screen, appearance }: { screen: Screen; appearance: Appearance }) {
  return (
    <div className="placeholder stack">
      <div className="top"><div><h1>{screen.label}</h1><p className="muted small">{screen.summary}</p></div></div>
      <section className="card stack">
        <div className="row">
          <div className="milestone">{screen.milestone}</div>
          <div className="grow">
            <h2>Arrives in milestone {screen.milestone}</h2>
            <p className="muted small">See docs/PLAN.md §9{screen.mockup ? ` and the mockup docs/mockups/${screen.mockup}.html` : ""}.</p>
          </div>
        </div>
        <div className="row small">
          <span className="badge b-info">Designed in {lookById(screen.look).name}</span>
          {appearance.look === "auto" ? <span className="muted">Showing in its own look.</span> : <span className="muted">Showing in {lookById(appearance.look).name}. <Link href="/appearance">Change look</Link></span>}
        </div>
      </section>
    </div>
  );
}
