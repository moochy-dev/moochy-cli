# `moochy-keylog` — Node key-log verifier, monitor, sealing gate

Formats and rules: `spec/KEYLOG.md`. How mo-node wires it: `WIRING.md`. Dependencies: `sha2`,
`ed25519-zebra` (ZIP-215); feature `http` (off by default) adds a blocking fetcher on `rustls`
(ring) + `webpki-roots`. No `unsafe`, no panics, every input bounded.

| Module | What |
|---|---|
| `monitor` | `Monitor::open(Config)` (restores from disk), `Monitor::run(&mut impl LogLink, on_event)`, `on_checkpoint`, `on_anchor`; `Event` (`message()`, `is_security()`); `View` (cloneable, fail closed): `gate()`, `seal_check(worker, repo, key_idx, approval_idx)`, `gateway_allowed(gateway, repo)`, `sealable`, `state(|s| …)`; `Gate` = `NoCheckpoint` / `Verified` / `Stale` / `Forked`; `MAX_LOG_AGE`, `POLL_EVERY` |
| `mirror` | `Mirror` (full incremental mirror, `update(cp, records)` all-or-nothing, `check(cp)` → `AnchorStatus`, `restore`), `Me { pseudonym, known_keys }`, `set_owner_keys`, `Alert` |
| `state` | the authority state machine (`apply`), `sealable` (repo or covering org approval, §19), `person_sealable` (the §24.4 person rule alone), `sealable_for` (`sealable`, else the person rule), `gateway_allowed`, `owner_key`, `active_owner_key`, `owner`, `owned_orgs`, `owned_people`, `donor_approved`, `device`, `catalog_sha256`; `Code` (stable strings) |
| `entry` | record/body parsing (`parse_record`, `parse_body`), `Kind` (`from_name`), builders for what the owner's CLI signs: `owner_key_body`, `claim_body`, `grant_body`, `org_claim_body`, `org_repo_body`, `person_claim_body`, `person_repo_body`, `owner_key_id`, `sig_message`, `pop_message` |
| `note` | `NoteKey::parse(vkey)`, `open_checkpoint(note, origin, key)` |
| `cosig` | `CosignerKey::parse(vkey)`, `cosignatures(note, &witnesses)` (C2SP cosignature/v1) |
| `receipts` | `record`, `leaf`, `verify(receipt, index, &cp, &proof)` (receipt transparency log) |
| `merkle` | `verify_inclusion`, `verify_consistency` (RFC 9162), `CompactRange`, `root_of` |
| `tiles` | C2SP paths (`tile_path`, `bundles`), `parse_bundle`, size caps |
| `fetch` (http) | `Fetcher::new(base, timeout)`, `get(path, max)`, `sync(&mut Mirror)` |

Tests: `cargo test -p moochy-keylog` (units, `tests/vectors.rs` against `spec/vectors/keylog/*.json`,
`tests/monitor.rs`: monitor loop, persistence, fork/stale/rollback, witness threshold, sealing gate
and its cost); `cargo clippy -p moochy-keylog --features http --all-targets -- -D warnings`. The Go
test `TestE2E_KeyLogMonitorVsLiveLog` drives `examples/keylog-check.rs` (the same `Monitor`) against
a live relay log.
