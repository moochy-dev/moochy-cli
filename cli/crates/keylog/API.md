# `moochy-keylog` — Node key-log verifier, mirror and monitor

Formats and rules: `spec/KEYLOG.md`. Owner: `mo-keylog`; wired into the Node by `mo-node`.
Dependencies: `sha2`, `ed25519-zebra` (ZIP-215). Feature `http` (off by default) adds a blocking
fetcher on `rustls` (ring) + `webpki-roots`. No `unsafe`, no panics, bounded inputs everywhere.

## Mirror (every Node)

```rust
let key = NoteKey::parse("moochy.dev/keylog+abcd1234+AQ…")?;   // pinned in config / release
let mut m = Mirror::new("moochy.dev/keylog", key.clone());
// or, at start-up, from what you persisted (no signature re-checks, root must match):
let mut m = Mirror::restore(origin, key, stored_records.iter().map(Vec::as_slice), &stored_cp)?;
m.set_me(Some(Me { pseudonym: my_ps, known_keys: vec![my_sign_pub /* + keys the user acknowledged */] }));

// Each Hello.log_checkpoint / LogCheckpoint push (≤ 60 s):
let cp = m.open_checkpoint(&note_bytes)?;                    // signature + origin + strict text
for b in tiles::bundles(m.size(), cp.size) {                 // fetch "tile/entries/…" (b.path())
    let recs = tiles::parse_bundle(&bytes, b.width)?;        // skip b.skip leading records
}
let alerts = m.update(&cp, &new_records)?;                   // all-or-nothing; Err(Error::Fork{..}) on any rewrite
// persist new_records (u16-BE length-prefixed) + the note; surface alerts to the user.
```

With feature `http`: `fetch::Fetcher::new("https://relay/log/", timeout)?.sync(&mut m)?` does the
checkpoint + bundle fetches (HTTP/1.0, TLS 1.3, size caps per object, deadline per request) and
returns `Synced { checkpoint, note, records, alerts }`.

## Fork and anchor checks

```rust
match m.check(&m.open_checkpoint(&git_anchor_note)?) {        // hourly, from the public Git repo
    AnchorStatus::Consistent => {}
    AnchorStatus::Behind => { /* sync; if the relay still serves less: rollback alert */ }
    AnchorStatus::Fork => { /* the log was forked: alert, stop trusting new entries */ }
}
```

`merkle::verify_inclusion` / `merkle::verify_consistency` (RFC 9162) verify proofs from any
third party (e.g. `moochy verify` bundles, witness cosigning later).

## Alerts

`UnknownKey` (new key on my account), `KeyHijack` (my key under another account),
`NotSignedByMe` (claim/approval/membership on my repo not signed by a known key of mine),
`RepoClaimedByOther`, `Rejected { code }` / `Invalid` (relay appended an invalid entry).
Monitor dedup/acknowledgement is the Node's job (add acknowledged keys to `Me::known_keys`).

## The two pure questions

```rust
// Gateway, before sealing (and to check pool.sync's key_log_index / approval_log_index):
let s = m.state().sealable(worker_device, repo_id)?;   // Sealable { enc_pub, key_idx, approval_idx }
// Worker, before acking (03 §7.2 checks 1–2; then verify task_sig with dev.sign_pub):
let dev = m.state().gateway_allowed(gateway_device, repo_id)?;
```

Errors are `state::Code` (`unknown_device`, `revoked`, `role`, `scope`, `unclaimed`,
`not_approved`, `not_member`). Other lookups: `device`, `device_by_key`, `owner`, `catalog_sha256`.

## Building owner-signed entries (owner's Node)

```rust
let body = entry::grant_body(repo_id, donor_ps, my_device_id, now_ms);    // or claim_body(...)
let sig = signing_key.sign(&entry::sig_message(Kind::DonorApproved, &body));
// send (kind, body, sig) to the relay; the relay appends it verbatim.
let pop = signing_key.sign(&entry::pop_message(&sign_pub, &enc_pub, suite)); // at DeviceStart
```

## Tests

`cargo test -p moochy-keylog` (unit + `tests/vectors.rs` against `spec/vectors/keylog/*.json`);
`cargo clippy -p moochy-keylog --features http --all-targets -- -D warnings`. The Go test
`TestE2E_ForkDetectedByRustVerifier` drives `examples/keylog-check.rs` against a live relay log.
