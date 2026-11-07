import { Fragment } from "react";
import { api } from "./api.ts";
import type { Appearance } from "./looks/looks.ts";
import { Link } from "./router.tsx";
import { screenById, screenGroups, screenPlaces, screens, type Screen } from "./screens.ts";

export function Brand({ appearance, href }: { appearance: Appearance; href?: string }) {
  const body = (
    <>
      <span className="glyph" aria-hidden="true">{appearance.glyph}</span>
      <span>
        {appearance.name}
        {appearance.tagline && <span className="tagline">{appearance.tagline}</span>}
      </span>
    </>
  );
  return href ? <Link className="brand" href={href}>{body}</Link> : <div className="brand">{body}</div>;
}

export function Sidebar({ appearance, current, short = false, onSignedOut }: { appearance: Appearance; current: Screen; short?: boolean; onSignedOut: () => void }) {
  const signOut = async () => {
    await api("POST", "/api/logout").catch(() => {});
    onSignedOut();
  };
  const link = (screen: Screen) => (
    <Link key={screen.id} className="nav" href={screen.path} aria-current={screen.id === current.id ? "page" : undefined}>
      <span className="icon" aria-hidden="true">{screen.icon}</span>
      {screen.label}
    </Link>
  );
  const places = screenPlaces.map(screenById).filter((s): s is Screen => Boolean(s));
  const rest = screens.filter((s) => !screenPlaces.includes(s.id));
  return (
    <nav className="side" aria-label="Screens">
      <Brand appearance={appearance} href="/" />
      {short ? (
        <>
          {places.map(link)}
          <details className="more" open={rest.some((s) => s.id === current.id)}>
            <summary className="sep">More</summary>
            {rest.map(link)}
          </details>
        </>
      ) : screenGroups.map((group) => (
        <Fragment key={group}>
          <div className="sep">{group}</div>
          {screens.filter((screen) => screen.group === group).map(link)}
        </Fragment>
      ))}
      <div className="foot">
        <span>Version {__THEYSPY_VERSION__}</span>
        <button className="btn small" type="button" onClick={signOut}>Sign out</button>
      </div>
    </nav>
  );
}
