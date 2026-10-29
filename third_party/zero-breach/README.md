# zero-breach (vendored)

Files copied unchanged from [interplains/zero-breach](https://github.com/interplains/zero-breach), the AdFection / Candiru scanner and indicator set by archivegenocide.com.

| | |
| --- | --- |
| Upstream commit | `1c7e9b6df81ea45982ec7d0f4fb607ffbbd55e00` (main, after tag `v0.1.8`) |
| Indicator set | `iocs/adfection_iocs.txt`, as-of 2026-10-18, 405 indicators |
| SHA-256 | `c9801e3ba37376535a676d9938d65550bcaa5478578cb80a6dd09eb2ac402d38` (matches `iocs/adfection_iocs.txt.sha256` and the signed v0.1.8 `SHA256SUMS.txt`) |
| Signing key | ArchiveGenocide Ed25519, fingerprint `C24E C92B 12D6 670A 2516 065F 9B4D 5754 99AF A53C` |

## What is here and why

- `iocs/`: the indicator set and its published hash. **CC0 1.0** (see `iocs/LICENSE.md`). TheySpy seeds its indicator store from this file on first start, after checking the hash.
- `build/stix-first-published.json`, `build/stix-withdrawals.json`: inputs to zero-breach's STIX emitter (first-publication dates and permanent withdrawals). TheySpy's STIX export reads them so its bundle has the same ids and dates.
- `dist/`: zero-breach's own generated exports for this commit. They are test fixtures: TheySpy's exports must match them byte for byte (`server/iocs/exports.test.mjs`).
- `release-signatures/v0.1.8/`: the signed release manifest and the public key. Tests check that TheySpy's OpenPGP verifier accepts this signature and that the manifest lists the vendored indicator file's hash.

Everything except `iocs/` and `dist/` is **Apache-2.0** (`LICENSE`, `NOTICE`). The emitter wording TheySpy reproduces (tier descriptions, source citations) comes from `build/emit_stix.py` and `build/emit_misp.py` under the same licence.

TheySpy is not affiliated with zero-breach, archivegenocide.com, The Citizen Lab or Confiant; see `NOTICE`.

## Updating

TheySpy's own updater (Indicators screen → Check for updates) fetches newer sets at runtime; this folder only changes when the bundled starting set is refreshed. To refresh it, copy the same files from a newer upstream commit, update the table above, and run `npm run check`.
