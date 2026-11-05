/**
 * A fixed-window counter per key (normally the client address), for the routes that answer
 * without a session: agent enrollment and reports, and bearer-token checks. The owner's own
 * sign-in has its own lockout (auth.mjs).
 *
 * A hit may cost more than one, so a request that does several pieces of work — an MCP batch is
 * one POST carrying many calls — is charged for all of them.
 * @param {{ limit: number, windowMs: number, now?: () => number }} options
 */
export function createRateLimit({ limit, windowMs, now = () => Date.now() }) {
  /** @type {Map<string, { start: number, count: number }>} */
  const windows = new Map();
  // Keys are dropped a window at a time rather than when the map passes a size, so the sweep
  // happens once a window however many callers there are, instead of on every request under load.
  let sweptAt = 0;

  const limiter = {
    /**
     * Counts `cost` hits; returns 0 when allowed, or the seconds to wait.
     * @param {string} key @param {number} [cost]
     */
    hit(key, cost = 1) {
      const t = now();
      if (t - sweptAt >= windowMs) {
        sweptAt = t;
        for (const [k, w] of windows) if (t - w.start >= windowMs) windows.delete(k);
      }
      const w = windows.get(key);
      if (!w || t - w.start >= windowMs) {
        windows.set(key, { start: t, count: cost });
        return cost > limit ? Math.ceil(windowMs / 1000) : 0;
      }
      w.count += cost;
      return w.count > limit ? Math.ceil((w.start + windowMs - t) / 1000) : 0;
    },

    /** How many keys are being counted right now (for tests). */
    size: () => windows.size,

    /** Express middleware counting every request. */
    middleware() {
      return (req, res, next) => {
        const wait = limiter.hit(req.ip ?? "unknown");
        if (!wait) return next();
        res.set("Retry-After", String(wait)).status(429).json({ error: "Too many requests; try again shortly" });
      };
    },
  };
  return limiter;
}
