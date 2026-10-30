/**
 * A fixed-window counter per key (normally the client address), for the routes that answer
 * without a session: agent enrollment and reports, and bearer-token checks. The owner's own
 * sign-in has its own lockout (auth.mjs).
 * @param {{ limit: number, windowMs: number, now?: () => number }} options
 */
export function createRateLimit({ limit, windowMs, now = () => Date.now() }) {
  /** @type {Map<string, { start: number, count: number }>} */
  const windows = new Map();
  return {
    /** Counts one hit; returns 0 when allowed, or the seconds to wait. @param {string} key */
    hit(key) {
      const t = now();
      if (windows.size > 10_000) for (const [k, w] of windows) if (t - w.start >= windowMs) windows.delete(k);
      const w = windows.get(key);
      if (!w || t - w.start >= windowMs) { windows.set(key, { start: t, count: 1 }); return 0; }
      w.count += 1;
      return w.count > limit ? Math.ceil((w.start + windowMs - t) / 1000) : 0;
    },
    /** Express middleware counting every request. */
    middleware() {
      return (req, res, next) => {
        const wait = this.hit(req.ip ?? "unknown");
        if (!wait) return next();
        res.set("Retry-After", String(wait)).status(429).json({ error: "Too many requests; try again shortly" });
      };
    },
  };
}
