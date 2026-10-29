import { productVersion } from "../shared.mjs";

// A client for Pi-hole v6's REST API, shaped by what a live Pi-hole 6 (FTL v6.7) actually does:
//  - POST /api/auth gives a session id, sent back as the X-FTL-SID header (no CSRF token needed
//    with the header). Sessions are a limited pool, so every use ends with DELETE /api/auth.
//  - GET /api/queries pages newest-first: keep the first response's `cursor` and step `start`.
//    `disk=true` reads the long-term database, which lags the in-memory log by up to a minute.
//  - A `domain` filter of `*name` is a plain suffix match (it also matches "notname"), so callers
//    apply their own label-boundary check.
//  - An exact deny entry does not block subdomains; Pi-hole's "wildcard" regex `(\.|^)name$` does.
//  - While gravity is being rebuilt, writes to groups, clients and lists fail with 400 "Could not add
//    to gravity database" for a few seconds; they succeed when retried.

export class PiholeError extends Error {
  /** @param {string} message @param {{ status?: number, cause?: unknown }} [options] */
  constructor(message, { status, cause } = {}) {
    super(message, { cause });
    this.status = status;
  }
}

/** Pi-hole's own wildcard pattern for a domain and all its subdomains. */
export function wildcardRegex(domain) {
  return `(\\.|^)${domain.replace(/[.*+?^${}()|[\]\\]/g, "\\$&")}$`;
}

const pageSize = 1000;
const maxPages = 500; // 500,000 queries per filter: far beyond a household, a ceiling against runaway paging

/**
 * @param {{ url: string, password: string | null, fetchImpl?: typeof fetch, timeoutMs?: number, retries?: number, retryDelayMs?: number }} options
 */
export function createPiholeClient({ url, password, fetchImpl = fetch, timeoutMs = 20_000, retries = 6, retryDelayMs = 1000 }) {
  const base = new URL("api/", url.endsWith("/") ? url : `${url}/`);
  if (base.protocol !== "http:" && base.protocol !== "https:") throw new PiholeError("The Pi-hole address must start with http:// or https://");
  let sid = null;

  async function call(method, path, body, options = {}) {
    for (let attempt = 1; ; attempt += 1) {
      try {
        return await callOnce(method, path, body, options);
      } catch (error) {
        const busy = method !== "GET" && error.status === 400 && /gravity database|database is locked/i.test(error.message);
        if (!busy || attempt >= retries) throw error;
        await new Promise((resolve) => setTimeout(resolve, retryDelayMs * attempt));
      }
    }
  }

  async function callOnce(method, path, body, { auth = true } = {}) {
    let response;
    try {
      response = await fetchImpl(new URL(path, base), {
        method,
        headers: { "user-agent": `TheySpy/${productVersion}`, ...(body === undefined ? {} : { "content-type": "application/json" }), ...(auth && sid ? { "X-FTL-SID": sid } : {}) },
        body: body === undefined ? undefined : JSON.stringify(body),
        redirect: "error",
        signal: AbortSignal.timeout(timeoutMs),
      });
    } catch (error) {
      throw new PiholeError(`Could not reach Pi-hole at ${base.origin}: ${error.cause?.code ?? error.message}`, { cause: error });
    }
    const text = await response.text();
    let data = null;
    try { data = text ? JSON.parse(text) : null; } catch { /* not JSON: an error page */ }
    if (!response.ok) {
      const detail = data?.error?.message ?? data?.error?.key ?? (text.slice(0, 120) || response.statusText);
      throw new PiholeError(`Pi-hole answered ${response.status} to ${method} /api/${path}: ${detail}`, { status: response.status });
    }
    return data;
  }

  const client = {
    origin: base.origin,

    /** Signs in. A Pi-hole without a password answers valid with no session id. */
    async login() {
      let data;
      try {
        data = await call("POST", "auth", { password: password ?? "" }, { auth: false });
      } catch (error) {
        if (error.status === 401) throw new PiholeError("Pi-hole refused the password. Use the web password or an app password from Settings → Web interface / API.", { status: 401 });
        throw error;
      }
      if (!data?.session?.valid) throw new PiholeError("Pi-hole did not accept the sign-in");
      sid = data.session.sid ?? null;
      return { totp: Boolean(data.session.totp) };
    },

    /** Gives the session back so it does not use up one of Pi-hole's session slots. */
    async logout() {
      if (!sid) return;
      try { await call("DELETE", "auth"); } catch { /* the session expires on its own */ }
      sid = null;
    },

    /** Runs `work` signed in, and always signs out afterwards. */
    async session(work) {
      await client.login();
      try { return await work(client); } finally { await client.logout(); }
    },

    async version() {
      const data = await call("GET", "info/version");
      return { core: data?.version?.core?.local?.version ?? null, ftl: data?.version?.ftl?.local?.version ?? null, web: data?.version?.web?.local?.version ?? null };
    },

    /**
     * Every query matching the filter, newest first, across all pages.
     * @param {{ from?: number, until?: number, domain?: string, client?: string, disk?: boolean }} filter Unix seconds
     */
    async queries({ from, until, domain, client: clientIp, disk = false } = {}) {
      const out = [];
      let cursor = null;
      for (let page = 0; page < maxPages; page += 1) {
        const params = new URLSearchParams({ length: String(pageSize), start: String(page * pageSize) });
        if (from !== undefined) params.set("from", String(Math.floor(from)));
        if (until !== undefined) params.set("until", String(Math.ceil(until)));
        if (domain) params.set("domain", domain);
        if (clientIp) params.set("client_ip", clientIp);
        if (disk) params.set("disk", "true");
        if (cursor !== null) params.set("cursor", String(cursor));
        const data = await call("GET", `queries?${params}`);
        if (cursor === null) cursor = data?.cursor ?? null;
        const rows = data?.queries ?? [];
        out.push(...rows);
        if (rows.length < pageSize || out.length >= (data?.recordsFiltered ?? 0) || cursor === null) break;
      }
      return out;
    },

    /** The names the network looks up most (answered, not blocked). */
    async topDomains(count = 200) {
      const data = await call("GET", `stats/top_domains?count=${count}&blocked=false`);
      return (data?.domains ?? []).map((d) => String(d.domain));
    },

    /** Whether Pi-hole would block a name, and why: its own lists or its adlists (gravity). */
    async search(domain) {
      const data = await call("GET", `search/${encodeURIComponent(domain)}?partial=false&N=50`);
      return data?.search ?? { domains: [], gravity: [], results: { domains: { exact: 0, regex: 0 }, gravity: { allow: 0, block: 0 }, total: 0 } };
    },

    /** @param {"allow" | "deny"} type @param {"exact" | "regex"} kind */
    async listDomains(type, kind) {
      return (await call("GET", `domains/${type}/${kind}`))?.domains ?? [];
    },

    /** The devices that ask Pi-hole most, with their names when Pi-hole knows them. */
    async topClients(count = 50) {
      const data = await call("GET", `stats/top_clients?count=${count}`);
      return (data?.clients ?? []).map((c) => ({ ip: String(c.ip), name: c.name || null, queries: Number(c.count ?? 0) }));
    },

    /** Names with how often they were looked up (and blocked), from Pi-hole's in-memory stats. */
    async topDomainCounts(count = 2000) {
      const [allowed, blocked] = await Promise.all([call("GET", `stats/top_domains?count=${count}&blocked=false`), call("GET", `stats/top_domains?count=${count}&blocked=true`)]);
      return [
        ...(allowed?.domains ?? []).map((d) => ({ domain: String(d.domain), queries: Number(d.count ?? 0), blocked: 0 })),
        ...(blocked?.domains ?? []).map((d) => ({ domain: String(d.domain), queries: Number(d.count ?? 0), blocked: Number(d.count ?? 0) })),
      ];
    },

    async listGroups() { return (await call("GET", "groups"))?.groups ?? []; },
    async addGroup(name, comment) {
      const data = await call("POST", "groups", { name, comment, enabled: true });
      return (data?.groups ?? []).find((g) => g.name === name) ?? null;
    },
    async deleteGroup(name) { await call("DELETE", `groups/${encodeURIComponent(name)}`); },

    async listClients() { return (await call("GET", "clients"))?.clients ?? []; },
    async addClient(client, groups, comment) { await call("POST", "clients", { client, groups, comment }); },
    async updateClient(client, groups, comment) { await call("PUT", `clients/${encodeURIComponent(client)}`, { groups, comment }); },
    async deleteClient(client) { await call("DELETE", `clients/${encodeURIComponent(client)}`); },

    /** Pi-hole's adlists (subscriptions) of one type. */
    async listAdlists(type = "block") {
      return (await call("GET", `lists?type=${type}`))?.lists ?? [];
    },

    /** Subscribes Pi-hole to a list URL for some groups; the type goes in the query string, as FTL requires. */
    async addAdlist(address, comment, groups = [0]) {
      await call("POST", "lists?type=block", { address, comment, groups, enabled: true });
    },

    async deleteAdlist(address) {
      await call("DELETE", `lists/${encodeURIComponent(address)}?type=block`);
    },

    /** Rebuilds gravity (downloads every adlist); returns Pi-hole's own log of it. */
    async updateGravity() {
      let response;
      try {
        response = await fetchImpl(new URL("action/gravity", base), { method: "POST", headers: { "user-agent": `TheySpy/${productVersion}`, ...(sid ? { "X-FTL-SID": sid } : {}) }, redirect: "error", signal: AbortSignal.timeout(10 * 60_000) });
      } catch (error) {
        throw new PiholeError(`Could not reach Pi-hole at ${base.origin}: ${error.cause?.code ?? error.message}`, { cause: error });
      }
      const text = await response.text();
      if (!response.ok) throw new PiholeError(`Pi-hole answered ${response.status} to its gravity update`, { status: response.status });
      // eslint-disable-next-line no-control-regex -- stripping the terminal colour codes in Pi-hole's gravity log
      return text.replace(/\x1b\[[0-9;]*[A-Za-z]/g, "");
    },

    /** Adds deny-regex entries in one request; returns what Pi-hole says it processed. */
    async addDenyRegex(patterns, comment) {
      const data = await call("POST", "domains/deny/regex", { domain: patterns, comment, groups: [0], enabled: true });
      return data?.processed ?? { success: [], errors: [] };
    },

    async deleteDenyRegex(patterns) {
      if (!patterns.length) return;
      // "./" so the colon is not read as a URL scheme ("domains:" would replace the whole address).
      await call("POST", "./domains:batchDelete", patterns.map((item) => ({ item, type: "deny", kind: "regex" })));
    },
  };
  return client;
}
