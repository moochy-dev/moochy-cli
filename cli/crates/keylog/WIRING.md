# Wiring `moochy-keylog` into the Node (for mo-node)

Formats and rules: `spec/KEYLOG.md`. Everything below is a few lines in `cli/crates/node`.

## 1. Implement `LogLink` on your link type

```rust
struct KeyLogLink {
    client: NodeLinkClient<Channel>,          // the authenticated relay link you already have
    notes: tokio::sync::mpsc::Receiver<Vec<u8>>, // Hello.log_checkpoint + every RelayMsg.log_checkpoint
    anchor_url: Option<String>,               // raw URL of the public Git anchor file (config)
    anchor_due: tokio::time::Instant,
}

impl moochy_keylog::LogLink for KeyLogLink {
    async fn get_tile(&mut self, path: &str) -> Result<Vec<u8>, moochy_keylog::Error> {
        let r = self.client.get_log_tile(LogTileRequest { path: path.into() }).await
            .map_err(|e| moochy_keylog::Error::Io(e.code().to_string()))?;
        Ok(r.into_inner().data)                   // size is re-checked by the monitor
    }
    async fn next_checkpoint(&mut self) -> Option<Vec<u8>> {
        // A pushed note, or poll every POLL_EVERY (60 s) so the gate stays fresh.
        match tokio::time::timeout(moochy_keylog::monitor::POLL_EVERY, self.notes.recv()).await {
            Ok(n) => n,                           // None = link closed → run() returns
            Err(_) => self.get_tile("checkpoint").await.ok(),
        }
    }
    async fn anchor(&mut self) -> Option<Vec<u8>> {
        // At most hourly: GET the anchor file over HTTPS with your client (≤ 8 KiB, 10 s timeout).
        None // until the public anchor URL is configured
    }
}
```

Session code: on `Hello`, send `hello.log_checkpoint` (if non-empty) into the `notes` channel;
on `RelayMsg::LogCheckpoint(n)` send `n.note`. Use a bounded channel of 1 with `try_send`
(latest wins): the monitor only needs the newest note.

## 2. Start the monitor once per relay

```rust
use moochy_keylog::{monitor::Config, Me, Monitor, NoteKey};
let mut mon = Monitor::open(Config {
    origin: "moochy.dev/keylog".into(),
    key: NoteKey::parse(PINNED_LOG_VKEY)?,      // compiled in for the default relay; config for dev relays
    dir: Some(home.join("state/keylog")),       // records, checkpoint, fork-evidence
    me: Some(Me {
        pseudonym,                              // from DevicePoll / Welcome
        known_keys: vec![device_sign_pub],      // + keys the user acknowledged
    }),
    known_owner_keys,                           // public halves of the user's owner keys (§4), if any
    witnesses: vec![],                          // pinned witness vkeys once witnesses run
    min_cosignatures: 0,
})?;
let view = mon.view();                          // clone it into the Gateway and the Worker
tokio::spawn(async move {
    mon.run(&mut link, |e| {
        if e.is_security() { tracing::warn!("{}", e.message()) /* + `moochy status` banner */ }
        else { tracing::info!("{}", e.message()) }
    }).await
});
```

`Monitor::open` restores from disk without network; persistence writes are small appends
(a few hundred bytes per new entry, one rename per checkpoint), off the data plane.
The messages carry the stable keywords the E2E tests grep (`unknown_key`, `unknown_owner_key`,
`unsigned`, `fork`, `stale checkpoint`, `rollback`). Write them to the Node log as given.

## 3. Gateway: the sealing rule (replaces D14 outside `--dev`)

For every `PoolSync.workers[]` entry, and again right before sealing a task:

```rust
match view.seal_check(&w.worker_device, &repo_id, w.key_log_index, w.approval_log_index) {
    Ok(s) => { /* seal to s.enc_pub (and require s.enc_pub == w.enc_pub) */ }
    Err(Code::NoCheckpoint) if dev_mode => { /* D14 fallback: relay's pool as-is, --dev only */ }
    Err(code) => { /* do not seal; log code.as_str() once per worker */ }
}
```

`seal_check` = gate (`Verified`, else `no_checkpoint` / `stale_log` / `log_forked`) + `sealable`
in the verified log + exact `key_log_index` / `approval_log_index`. One read lock, three hash
lookups, no allocation: call it on the submit path. A worker the relay injects without a logged
owner approval never gets a wrap (E97). `view.gate()` gives the state for `moochy status`.

## 4. Worker: who may submit

```rust
let dev = view.gateway_allowed(&inner.gateway_device, &route.repo_id)?; // Err(code) → Nack unauthorized_task
// then verify task_sig with dev.sign_pub (03 §7.2)
```

Outside `--dev`, an `Err(Code::NoCheckpoint)` here is also a refusal (MOOCHY_INSECURE_DEV keeps the
D14 relay-asserted path for tests only).

## 5. Owner key (foreground CLI only, CONTRACT §15.4)

- `moochy owner init`: generate an Ed25519 owner key, store it encrypted at rest (scrypt/argon2 +
  the keystore passphrase, separate file, never loaded by `moochy up`), then submit
  `SignedLogEntry{kind:"OWNER_KEY_ADDED", body: entry::owner_key_body(ps, &pub, None, now_ms),
  sigs:[sign(sig_message(OwnerKeyAdded, body))]}` and add `pub` to the monitor's `known_owner_keys` (persist the public half in config).
- `moochy owner rotate`: body with `prev = Some(&old_pub)`, `sigs: [new_sig, old_sig]`.
- `moochy approve` / `members add|remove` / `claim`: take the `ApprovalRequest`, parse
  `body_to_sign` with `entry::parse_body(Kind::from_name(&r.kind)?, &r.body_to_sign)` (kind, repo,
  subject must match the request), **show the user what it means and ask for confirmation**, rebuild it with `entry::grant_body(repo, subject,
  &entry::owner_key_id(&owner_pub), now_ms)` (or `claim_body`), decrypt the owner key, sign
  `entry::sig_message(kind, &body)`, wipe the key, send `SignedLogEntry`. The background process
  never touches the owner key; it only relays the already-signed entry.

## 6. Receipts (donor side, optional now)

`receipts::verify(&receipt_bytes, index, &cp, &proof)` with `cp` opened from a receipt-log note
(origin `moochy.dev/receipts`, its own pinned key) and the proof fetched over the link once the
relay exposes it (`receipts/…` tile prefix or a proof field; see the report's requests).

## 7. Round additions (A203–A205, E63, device requests)

- **Fail-open warning (A204).** Implement `LogLink::anchor_configured()` → `true` when the
  public Git anchor URL is configured. With no anchor and `min_cosignatures == 0`,
  `Monitor::run` emits `Event::FailOpen` once (security event: show it in `moochy status`);
  `Monitor::fail_open(&link)` answers the same question for `moochy doctor`.
- **New own keys at runtime.** After `moochy keys rotate` or `moochy owner init/rotate`, call
  `view.acknowledge_device_key(pub)` / `view.acknowledge_owner_key(pub)` (and persist the key in
  config for the next `Monitor::open`); no need to reopen the monitor.
- **`moochy verify <receipt_ref>` (E63).** `monitor::fetch_projection(&mut link, ref)` returns the
  relay's JSON `{"projection_b64","sig_b64","worker_device","key_log_index"}` (≤ 16 KiB). Parse
  it with the Node's strict JSON parser, base64url-decode, then
  `view.verify_projection(&projection, &sig, &worker_device, key_log_index)` → donor pseudonym
  (+ `revoked`), checking the device's KEY_ADDED in your own mirror. Finally check the projection
  JSON names the requested `receipt_ref`.
- **Device requests (spec/KEYLOG.md §2a).** `moochy logout` / `keys revoke`:
  `SignedLogEntry{kind:"KEY_REVOKED", body: entry::revoke_body(id, ps, reason),
  sigs:[sign(entry::revoke_request_message(&body))]}` — NOT `sig_message` (refused). The session
  closes when its own device is revoked, so confirm via the KEY_REVOKED entry rather than the ack.
  `moochy keys rotate`: body `entry::key_body(...)` for the successor, `sigs:[successor PoP,
  current.sign(entry::rotate_request_message(&body))]`.
