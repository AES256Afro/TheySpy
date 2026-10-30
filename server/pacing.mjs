// Rate limits for every outside service TheySpy reads (feeds, directories, blocklists, NVD). Each
// host gets a minimum gap between requests and an hourly budget, and when a service says to slow
// down (429, or 503 with Retry-After) TheySpy holds back from it until the time it names. Short
// waits are waited out; a long one fails at once with a plain message rather than tying up a job.
// NVD and GitHub publish their limits; everything else gets a polite default.

/** Published limits, by host. A leading dot covers every name under the domain. */
export const hostBudgets = {
  // 60 requests an hour without a token; leave room for the owner's own use of the same address.
  "api.github.com": { minIntervalMs: 1_000, perHour: 50 },
  // 5 requests per 30 s without a key, 50 with one; the NVD code paces itself to that too. NVD says
  // "too many" with a 403, not a 429, and asks for 30 s of quiet.
  "services.nvd.nist.gov": { minIntervalMs: 600, perHour: 5_500, slowDown: [403], quietMs: 30_000 },
  default: { minIntervalMs: 250, perHour: 1_000 },
};

/** Seconds or an HTTP date, as Retry-After allows; null when absent or unreadable. */
export function retryAfterMs(value, nowMs) {
  if (!value) return null;
  if (/^\d+$/.test(value.trim())) return Number(value.trim()) * 1000;
  const at = Date.parse(value);
  return Number.isFinite(at) ? Math.max(0, at - nowMs) : null;
}

/**
 * @param {typeof fetch} baseFetch
 * @param {{
 *   budgets?: Record<string, { minIntervalMs: number, perHour: number, slowDown?: number[], quietMs?: number }>,
 *   maxWaitMs?: number,
 *   audit?: { record: (...args: any[]) => void },
 *   now?: () => number,
 *   sleep?: (ms: number) => Promise<void>,
 * }} [options]
 */
export function createPacedFetch(baseFetch, { budgets = hostBudgets, maxWaitMs = 120_000, audit, now = () => Date.now(), sleep = (ms) => new Promise((resolve) => setTimeout(resolve, ms)) } = {}) {
  /** @type {Map<string, { next: number, sent: number[], heldUntil: number, reported: number }>} */
  const hosts = new Map();
  const budgetOf = (host) => budgets[host] ?? Object.entries(budgets).find(([entry]) => entry.startsWith(".") && (host.endsWith(entry) || host === entry.slice(1)))?.[1] ?? budgets.default;
  const stateOf = (host) => {
    let state = hosts.get(host);
    if (!state) { state = { next: 0, sent: [], heldUntil: 0, reported: 0 }; hosts.set(host, state); }
    return state;
  };
  const clock = (ms) => new Date(ms).toISOString().slice(11, 16);

  /** @type {typeof fetch} */
  const paced = async (input, init) => {
    let host;
    try { host = new URL(input instanceof Request ? input.url : String(input)).hostname.toLowerCase(); } catch { return baseFetch(input, init); }
    const budget = budgetOf(host);
    const state = stateOf(host);
    // Reserve this request's slot before waiting, so concurrent callers queue behind each other.
    const t = now();
    state.sent = state.sent.filter((at) => t - at < 3_600_000);
    const hourFree = state.sent.length >= budget.perHour ? state.sent[state.sent.length - budget.perHour] + 3_600_000 : 0;
    const start = Math.max(t, state.next, state.heldUntil, hourFree);
    if (start - t > maxWaitMs) {
      const why = state.heldUntil >= start ? `${host} asked TheySpy to slow down` : `TheySpy's hourly budget for ${host} (${budget.perHour} requests) is used up`;
      throw Object.assign(new Error(`${why}; trying again after ${clock(start)} UTC`), { code: "TS_RATE_LIMITED", retryAt: new Date(start).toISOString() });
    }
    state.next = start + budget.minIntervalMs;
    state.sent.push(start);
    if (start > t) await sleep(start - t);
    const response = await baseFetch(input, init);
    if (response.status === 429 || (response.status === 503 && response.headers.get("retry-after")) || budget.slowDown?.includes(response.status)) {
      const wait = Math.min(retryAfterMs(response.headers.get("retry-after"), now()) ?? budget.quietMs ?? 60_000, 3_600_000);
      state.heldUntil = Math.max(state.heldUntil, now() + wait);
      if (now() - state.reported > 3_600_000) {
        state.reported = now();
        audit?.record("system", "egress.rate_limited", host, { status: response.status, until: new Date(state.heldUntil).toISOString() });
      }
    }
    return response;
  };

  return {
    fetch: paced,
    /** Hosts TheySpy is holding back from right now, for the Activity screen and tests. */
    held: () => [...hosts].filter(([, state]) => state.heldUntil > now()).map(([host, state]) => ({ host, until: new Date(state.heldUntil).toISOString() })),
  };
}
