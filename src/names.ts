import { useEffect, useState } from "react";
import { api } from "./api.ts";

export type KnownName = { id: number; name: string; from: string; network: string | null };

let cache: Promise<Record<string, KnownName>> | null = null;

/** Address → the device's best name, from the Fleet, so any screen can say who an address is. */
export function useNames() {
  const [names, setNames] = useState<Record<string, KnownName>>({});
  useEffect(() => {
    cache ??= api<{ names: Record<string, KnownName> }>("GET", "/api/fleet/names").then((r) => r.names, () => ({}));
    let live = true;
    void cache.then((n) => { if (live) setNames(n); });
    const timer = setTimeout(() => { cache = null; }, 60_000);
    return () => { live = false; clearTimeout(timer); };
  }, []);
  return names;
}
