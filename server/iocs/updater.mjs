import { readFileSync } from "node:fs";
import { productVersion } from "../shared.mjs";
import { parseIocText } from "./parse.mjs";
import { parseChecksums, readPublicKey, verifyDetached } from "./openpgp.mjs";
import { sha256 } from "./store.mjs";

// Fetches newer zero-breach indicator sets. Two tracks:
//  - "release" (default): the latest tagged release. Its SHA256SUMS.txt must carry a valid signature
//    from ArchiveGenocide's pinned Ed25519 key, and the indicator file must match the hash it lists.
//    That proves who published the bytes, not just that they arrived intact.
//  - "main": the development branch, checked against the .sha256 published beside it. Fresher, but
//    the hash comes from the same place as the file, so it proves integrity only (zero-breach's own
//    updater has this trust model and says so).
// Either way nothing is applied here: a fetched set becomes a pending version for the owner to review.

export const tracks = Object.freeze(["release", "main"]);
export const pinnedFingerprint = "C24EC92B12D6670A2516065F9B4D575499AFA53C";
const repository = "interplains/zero-breach";
const allowedHosts = new Set(["api.github.com", "raw.githubusercontent.com"]);
const maxBytes = 5 * 1024 * 1024;

const signingKey = (() => {
  const key = readPublicKey(readFileSync(new URL("../../third_party/zero-breach/release-signatures/v0.1.8/archivegenocide-signing-key.asc", import.meta.url), "utf8"));
  if (key.fingerprint !== pinnedFingerprint) throw new Error(`bundled signing key is ${key.fingerprint}, expected ${pinnedFingerprint}`);
  return key;
})();

export class UpdateError extends Error {}

/**
 * @param {{ fetchImpl?: typeof fetch, timeoutMs?: number }} [options]
 */
export function createIocUpdater({ fetchImpl = fetch, timeoutMs = 30_000 } = {}) {
  async function get(url) {
    const parsed = new URL(url);
    if (parsed.protocol !== "https:" || !allowedHosts.has(parsed.hostname)) throw new UpdateError(`refusing to fetch ${url}: not an allowed host`);
    let response;
    try {
      response = await fetchImpl(url, { headers: { "user-agent": `TheySpy/${productVersion}`, accept: "application/vnd.github+json, text/plain, */*" }, redirect: "error", signal: AbortSignal.timeout(timeoutMs) });
    } catch (error) {
      throw new UpdateError(`could not reach ${parsed.hostname}: ${error.message}`, { cause: error });
    }
    if (response.status === 404) return null;
    if (!response.ok) throw new UpdateError(`${parsed.hostname} answered ${response.status} for ${parsed.pathname}`);
    const body = Buffer.from(await response.arrayBuffer());
    if (body.length > maxBytes) throw new UpdateError(`${parsed.pathname} is larger than ${maxBytes} bytes`);
    return body;
  }
  const raw = (ref, path) => `https://raw.githubusercontent.com/${repository}/${ref}/${path}`;
  const required = async (url, what) => {
    const body = await get(url);
    if (!body) throw new UpdateError(`${what} was not found at ${url}`);
    return body;
  };

  async function fromRelease() {
    const latest = JSON.parse((await required(`https://api.github.com/repos/${repository}/releases/latest`, "the latest release")).toString("utf8"));
    const tag = String(latest.tag_name ?? "");
    if (!/^v\d+\.\d+\.\d+$/.test(tag)) throw new UpdateError(`unexpected release tag ${JSON.stringify(tag)}`);
    // Signatures are committed after the tag, so look on main first, then at the tag itself.
    const signed = async (name) => (await get(raw("main", `release-signatures/${tag}/${name}`))) ?? (await get(raw(tag, `release-signatures/${tag}/${name}`)));
    const manifest = await signed("SHA256SUMS.txt");
    const signature = await signed("SHA256SUMS.txt.asc");
    if (!manifest || !signature) throw new UpdateError(`release ${tag} has no signed SHA256SUMS.txt yet; try again later or use the main track`);
    let verified;
    try {
      verified = verifyDetached(manifest, signature.toString("utf8"), signingKey);
    } catch (error) {
      throw new UpdateError(`release ${tag}: the signature on SHA256SUMS.txt is not valid (${error.message})`, { cause: error });
    }
    const expected = parseChecksums(manifest.toString("utf8")).get("adfection_iocs.txt");
    if (!expected) throw new UpdateError(`release ${tag}: the signed manifest does not list adfection_iocs.txt`);
    const file = await required(raw(tag, "iocs/adfection_iocs.txt"), `release ${tag}'s indicator file`);
    if (sha256(file) !== expected) throw new UpdateError(`release ${tag}: the indicator file does not match the signed manifest (got ${sha256(file)}, signed ${expected})`);
    return { file, provenance: { track: "release", release: tag, signedBy: pinnedFingerprint, signedAt: verified.signedAt.toISOString(), note: `Signed release ${tag}: SHA256SUMS.txt verified with ArchiveGenocide's pinned Ed25519 key.` } };
  }

  async function fromMain() {
    const file = await required(raw("main", "iocs/adfection_iocs.txt"), "the indicator file on main");
    const published = (await required(raw("main", "iocs/adfection_iocs.txt.sha256"), "its published SHA-256")).toString("utf8").split(/\s+/)[0].toLowerCase();
    if (sha256(file) !== published) throw new UpdateError(`the file on main does not match its published SHA-256 (got ${sha256(file)}, published ${published})`);
    return { file, provenance: { track: "main", sha256: published, note: "Development branch. The hash is served from the same place as the file, so it proves the download is intact, not who published it." } };
  }

  return {
    /**
     * Downloads, verifies and parses a set. Throws UpdateError (or IocError for a malformed file);
     * never touches the database.
     * @param {"release" | "main"} track
     */
    async fetchCandidate(track) {
      const { file, provenance } = track === "main" ? await fromMain() : await fromRelease();
      const text = file.toString("utf8");
      parseIocText(text); // a truncated or malformed file stops here, before anything is stored
      return { raw: text, provenance };
    },
  };
}

/**
 * Job kinds for indicators. Checking is a job anyone signed in can start; applying runs only from
 * the review screen, with the version id.
 * @param {{ store: ReturnType<typeof import("./store.mjs").createIocStore>, updater: ReturnType<typeof createIocUpdater>, settings: ReturnType<typeof import("../db.mjs").createSettingsStore>, now?: () => Date }} deps
 */
export function iocJobKinds({ store, updater, settings, now = () => new Date() }) {
  const remember = (outcome) => settings.set("ioc_last_check", { at: now().toISOString(), ...outcome });
  return {
    "ioc.check": {
      title: "Check for indicator updates",
      direct: true,
      async run({ log, actor }) {
        const track = settings.get("ioc_track") ?? "release";
        log(`Checking zero-breach (${track} track).`);
        try {
          const candidate = await updater.fetchCandidate(track);
          log(candidate.provenance.note);
          const version = store.recordCandidate({ ...candidate, actor });
          if (!version) {
            log("Already up to date: the published set is identical to the active one.");
            remember({ track, outcome: "up-to-date" });
            return { upToDate: true };
          }
          const { added, removed, changed } = version.diff;
          log(`Update found: +${added.length} new, -${removed.length} removed, ~${changed.length} changed. Review it on the Indicators screen.`);
          remember({ track, outcome: "update-found", versionId: version.id });
          return { versionId: version.id };
        } catch (error) {
          remember({ track, outcome: "failed", message: error.message });
          throw error;
        }
      },
    },
    "ioc.apply": {
      title: "Apply an indicator update",
      async run({ log, params, actor }) {
        const version = store.apply(Number(params.versionId), actor);
        log(`Version ${version.id} is now active: ${version.count} indicators, as-of ${version.asof ?? "undated"}.`);
        return { versionId: version.id };
      },
    },
  };
}
