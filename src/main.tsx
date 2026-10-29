import "@fontsource-variable/inter";
import "@fontsource-variable/jetbrains-mono";
import "@fontsource-variable/source-serif-4";
import "@fontsource-variable/oswald";
import "./styles.css";
import { StrictMode } from "react";
import { createRoot } from "react-dom/client";
import { App } from "./App.tsx";
import { applyLook, lookById } from "./looks/looks.ts";

// Paint the default look before the first fetch so the page never flashes unstyled.
applyLook(document.documentElement, lookById("ops"), { accent: "", density: "comfortable" });

createRoot(document.getElementById("root")!).render(
  <StrictMode>
    <App />
  </StrictMode>,
);
