import { useCallback, useEffect, useMemo, useState } from "react";
import { api } from "./api.ts";
import { applyLook, mergeAppearance, readLocalAppearance, resolveLook, writeLocalAppearance, type Appearance } from "./looks/looks.ts";
import { usePath } from "./router.tsx";
import { screenById, screenForPath, screens, type Screen } from "./screens.ts";
import { Sidebar } from "./Sidebar.tsx";
import { SignIn } from "./SignIn.tsx";
import { ActivityScreen } from "./screens/Activity.tsx";
import { AppearanceScreen, type AppearanceControls } from "./screens/Appearance.tsx";
import { IndicatorsScreen } from "./screens/Indicators.tsx";
import { PiholeScreen } from "./screens/Pihole.tsx";
import { PlaceholderScreen } from "./screens/Placeholder.tsx";

type AppearanceResponse = { appearance: Appearance };

export function App() {
  const path = usePath();
  const [signedIn, setSignedIn] = useState<boolean | null>(null);
  const [server, setServer] = useState<Partial<Appearance>>({});
  const [local, setLocalState] = useState<Partial<Appearance>>(() => readLocalAppearance());
  const [preview, setPreview] = useState<Partial<Appearance> | null>(null);

  useEffect(() => {
    api<{ signedIn: boolean }>("GET", "/api/session").then((s) => setSignedIn(s.signedIn), () => setSignedIn(false));
    api<AppearanceResponse>("GET", "/api/appearance").then((r) => setServer(r.appearance), () => {});
  }, []);

  const appearance = useMemo(() => (preview ? mergeAppearance({ ...server, ...preview }, {}) : mergeAppearance(server, local)), [server, local, preview]);
  const screen: Screen = (path === "/" ? screenById(appearance.home) : screenForPath(path)) ?? screens[0];

  useEffect(() => {
    applyLook(document.documentElement, resolveLook(appearance.look, signedIn ? screen.look : "ops"), appearance);
    document.title = signedIn ? `${appearance.name} · ${screen.label}` : appearance.name;
  }, [appearance, screen, signedIn]);

  const setLocal = useCallback((next: Partial<Appearance>) => {
    writeLocalAppearance(next);
    setLocalState(next);
  }, []);

  if (signedIn === null) return null;
  if (!signedIn) return <SignIn appearance={appearance} onSignedIn={() => setSignedIn(true)} />;

  const controls: AppearanceControls = {
    appearance, server, local, setLocal, setPreview,
    saveForEveryone: async (value) => setServer((await api<AppearanceResponse>("PUT", "/api/appearance", value)).appearance),
    resetForEveryone: async () => setServer((await api<AppearanceResponse>("DELETE", "/api/appearance")).appearance),
  };

  return (
    <div className="app">
      <Sidebar appearance={appearance} current={screen} onSignedOut={() => setSignedIn(false)} />
      <main id="main">
        {screen.id === "appearance" ? <AppearanceScreen {...controls} /> : screen.id === "activity" ? <ActivityScreen /> : screen.id === "indicators" ? <IndicatorsScreen /> : screen.id === "pihole" ? <PiholeScreen /> : <PlaceholderScreen screen={screen} appearance={appearance} />}
      </main>
    </div>
  );
}
