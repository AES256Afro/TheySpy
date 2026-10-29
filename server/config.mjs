import path from "node:path";

/**
 * Everything TheySpy reads from the environment, in one place. BoxPilot sets these from the
 * catalog manifest (boxpilot/theyspy.yaml); standalone, they come from .env or the shell.
 * @param {Record<string, string | undefined>} env
 */
export function readConfig(env = process.env) {
  const port = Number(env.TS_PORT ?? 8797);
  if (!Number.isInteger(port) || port < 1 || port > 65535) throw new Error(`TS_PORT must be a port number, got "${env.TS_PORT}"`);
  return {
    host: env.TS_HOST ?? "0.0.0.0",
    port,
    dataDirectory: path.resolve(env.TS_DATA_DIR ?? "data"),
    adminPassword: env.TS_ADMIN_PASSWORD?.trim() || null,
    sessionSecret: env.TS_SESSION_SECRET?.trim() || null,
    cookieSecure: env.TS_COOKIE_SECURE === "true",
    // Daily look for a newer indicator set (it is only offered for review, never applied).
    iocAutoCheck: env.TS_IOC_AUTOCHECK !== "false",
    // Pi-hole: these override what the owner sets on the Pi-hole Sentinel screen.
    pihole: {
      url: env.TS_PIHOLE_URL?.trim() || undefined,
      password: env.TS_PIHOLE_PASSWORD || undefined,
      dbPath: env.TS_PIHOLE_DB?.trim() || undefined,
      write: env.TS_PIHOLE_WRITE === undefined || env.TS_PIHOLE_WRITE === "" ? undefined : env.TS_PIHOLE_WRITE === "true",
    },
    appearance: {
      look: env.TS_LOOK?.trim() || undefined,
      name: env.TS_BRAND_NAME?.trim() || undefined,
      tagline: env.TS_BRAND_TAGLINE?.trim() || undefined,
      accent: env.TS_ACCENT?.trim() || undefined,
    },
  };
}
