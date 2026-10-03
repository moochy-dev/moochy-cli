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

## 8. Passkey owner keys (`webauthn-es256`, CONTRACT §16.6, spec/KEYLOG.md §4a)

Accept in emails and on the web is signed by the human with a passkey: a WebAuthn assertion over
`SHA-256(sig_message(kind, body))`. Everything below is exact; the codes in the acks are the
spec's (`webauthn_*`, `counter`, `high_s`, `owner_key_exists`, `dup_key`, `skew`, …).

### 8a. mo-oauth: the web ceremonies (Go, `relay/internal/tlog` API)

- **Config.** `rpID` (e.g. `moochy.dev`) and `origins` (e.g. `https://moochy.dev`, ≤ 4,
  comma-joined, each host = rpID or a subdomain; dev `http://localhost:PORT`). The string is
  logged with each passkey and checked byte for byte against `clientDataJSON.origin`: changing
  domains later needs new passkeys.
- **First passkey (account without any owner key: `len(KeyLog.OwnerKeys(ps)) == 0`).**
  1. Email proof (A224): mail a one-time token to the confirmed address (mo-notify), redeemed in
     the same browser session within 10 min; keep only `tokenHash = sha256(token)`, single use.
  2. `navigator.credentials.create({publicKey: {rp: {id: rpID, name: "Moochy"}, user: {id:
     <16 random bytes>, name, displayName}, challenge: <random>, pubKeyCredParams: [{type:
     "public-key", alg: -7}], authenticatorSelection: {userVerification: "required", residentKey:
     "preferred"}, attestation: "none"}})`. Read `response.getPublicKey()` (SPKI DER) →
     `x509.ParsePKIXPublicKey` → `*ecdsa.PublicKey` (P-256 only, else refuse) → `x, y` (32 bytes
     each, `FillBytes`) → `cose := tlog.CoseKey(x, y)`; `credID := rawId` (1..255 bytes). No CBOR
     needed server-side; the create() challenge is not logged.
  3. `b := tlog.OwnerPasskey{Pseudonym: ps, Cose: cose, IssuedAtMs: nowMs, CredentialID: credID,
     RPID: rpID, Origins: origins, EmailProof: tlog.EmailProof(tokenHash, tlog.OwnerKeyID(cose),
     ps)}`; `body := b.Body()`. Keep `body` server-side (session-bound, ≤ 5 min); never rebuild it.
  4. `navigator.credentials.get({publicKey: {challenge: tlog.Challenge(tlog.SigMessage(
     tlog.OwnerKeyAdded, body)), rpId: rpID, allowCredentials: [{type: "public-key", id: credID}],
     userVerification: "required"}})` → `a := tlog.Assertion{AuthData: authenticatorData,
     ClientDataJSON: clientDataJSON, Signature: signature}` (raw bytes as the browser returns them).
  5. `KeyLog.Append(ctx, tlog.OwnerKeyAdded, body, tlog.PasskeySig(a, nil))`. Append checks
     everything (grammar, skew, PoP, first-key rule) and rewrites high-S to low-S itself.
- **Another passkey** (the user already has one): same steps without the email proof:
  `Authorizer: <ok_id of an active passkey>`, `EmailProof: nil`; after the new credential's get()
  (PoP), run a second get() with `allowCredentials: [authorizer's credential]` over the **same**
  challenge; `sig = tlog.PasskeySig(pop, authAssertion.Encode())`. An Ed25519 authorizer (CLI key)
  is valid in the log but has no web ceremony: not offered.
- **Accept (email button or web) = `DONOR_APPROVED`** (same for `DONOR_REVOKED`, `MEMBER_*`,
  `REPO_CLAIMED`): the signer id is inside the body, so pick the credential **before** signing:
  the passkey last used in this browser (store its `ok_` id in localStorage after registration /
  each approval), else a picker over `KeyLog.OwnerKeys(ps)` with `Alg == tlog.AlgWebAuthnES256`.
  `body := tlog.Grant{RepoID, Subject: donorPseudonym, Signer: k.ID, IssuedAtMs: nowMs}.Body()`
  (show the user what it means first: repo, donor, approve), then one get() with
  `challenge = tlog.Challenge(tlog.SigMessage(tlog.DonorApproved, body))`, `allowCredentials:
  [k.Passkey's credential: k.CredentialID]`, `userVerification: "required"`; then submit through
  mo-relay's gate (8b) with `sig = a.Encode()`. The email link itself never approves: it opens
  the page that runs the ceremony.
- **UX of refusals.** `counter`: "this passkey's signature counter went backwards; it may have
  been copied, use another one and revoke it"; `webauthn_origin`/`webauthn_rp`: wrong domain;
  `owner_key_exists`: the account already has an owner key (co-sign with it).
- **Revoking a passkey** (lost device, after re-authentication): relay-asserted
  `KeyLog.Append(ctx, tlog.OwnerKeyRevoked, tlog.OwnerRevoke{Pseudonym: ps, Pub: k.Pub /* 77-byte
  COSE */, Reason: "lost"}.Body(), nil)`. The user's Nodes alert on it.

### 8b. mo-relay: append path and gate

- **Append.** Passkey-signed kinds 3–7 go through the same `KeyLog.Append` /
  `AppendSigned(kind, body, [][]byte{a.Encode()})` (one sig of any length). Passkey
  `OWNER_KEY_ADDED` is refused by `AppendSigned` (it wants 64-byte sigs): web only, via `Append`.
  The log does the rest: low-S rewrite, record bound (≤ 2048 with an assertion, else 480), `PAD`
  entries before large records so every entry bundle stays ≤ 123,392 bytes (MaxTileBytes and the
  128 KiB gRPC limit are unchanged), per-credential counters (moved only when the entry commits),
  `KindByName` never yields `PAD` (`Append(PAD)` is refused).
- **Gate (`sched/keylog.go`, EvLogGate).** Replace `ActiveOwnerKey(ps).ID == signer` by "signer is
  one of `KeyLog.OwnerKeys(ps)`" (Ed25519 or passkey). Keep the verified-claimant / current-owner
  checks as they are.
- **ApprovalRequests to Nodes.** `hasKey := len(KeyLog.OwnerKeys(ps)) > 0`. Keep proposing bodies
  with `ActiveOwnerKey` (the CLI's Ed25519 key) when there is one; when the user has only passkeys,
  send no `owner_key` request (an Ed25519 first key would be refused with `owner_key_exists`) and
  leave approvals to the web/email flow.
- **Listings.** Anything that walks log entries for display (activity, admin) skips kind 12 `PAD`;
  `Entry.Parse()` returns `(nil, nil)` for it.

### 8c. mo-donor: Node verification

- **Nothing to call for verification**: the mirror's `State` verifies passkey entries (assertion,
  counter, first-key rule) and `sealable` / `gateway_allowed` work unchanged for passkey-signed
  approvals. New `Body` variants (`OwnerPasskey`, `OwnerPasskeyRevoke`, `Pad`) fall into your
  existing `_ =>` arms. Mac: `moochy-keylog` now depends on `ring` (already in the Node via rustls).
- **Required patch** (`crates/node/src/keylog.rs`, `alert_fields`, exhaustive match): add

  ```rust
  Alert::UnknownPasskey { idx, owner_key, rp_id, email_proof } => json!({"alert": "unknown_passkey", "idx": idx, "kind": "OWNER_KEY_ADDED", "owner_key": clean(owner_key), "rp_id": clean(rp_id), "email_proof": email_proof}),
  Alert::PasskeyCounter { idx, owner_key } => json!({"alert": "passkey_counter", "idx": idx, "code": "counter", "owner_key": clean(owner_key)}),
  ```

  (checked: with these two arms `cargo build -p moochy` and its tests build).
- **Known passkeys.** A Node names a passkey by `state::passkey_digest(cose_key)` (=
  `OwnerKeyInfo::owner_pub` for passkeys). Passkeys are created on the web, so the Node first
  sees them as `UnknownPasskey`; after the user confirms (`moochy owner trust <ok_id>` or the
  status UI), call `view.acknowledge_owner_key(digest)` with `digest = view.state(|s|
  s.owner_key(id).map(|k| k.owner_pub))` and persist it with the other known owner keys. Show
  `email_proof: true` prominently: the key was bound on the relay's word that the user's mailbox
  was proven (takeover path if the mailbox or relay is compromised).

## 9. Box devices (CONTRACT §17.1, spec/KEYLOG.md §2b) and the passkey-authorized CLI key (§4b)

### 9a. mo-relay: append path

- **Box KEY_ADDED.** In `edge/keylog.go` `keyBody`, add `Box: k.Box, ExpiresAtMs: uint64(k.ExpiresAtMs)`
  to the `tlog.Key`. In `sched` `enroll`, set `KeyInfo.Box = b.ID` (the `bt_…` token id, not a
  bool) and `KeyInfo.ExpiresAtMs = b.Expires`. Leave both zero for every other device.
  `Key.Body()` then emits the 9-field form. The grammar refuses a box that is not exactly
  `roles = "gateway"` with a repo scope. The state refuses an expiry outside
  `(logged_at, logged_at + 30 d]` (`box_expiry`), so a token that expired between `enroll` and
  `Append` fails. The existing "refused → revoke the device" path covers it. The PoP is
  unchanged.
- **Expiry.** `Log.GatewayAllowed` / `Log.Sealable` read `cfg.Now()` and return `expired` for a
  box at or after its expiry. `sched/core.go`'s `RequireLog` check therefore refuses expired boxes
  even before the relay logs the `KEY_REVOKED`. Keep logging `KEY_REVOKED` (`reason: "expired"`
  or `"box"`) at expiry or revocation: Nodes see revocations immediately and expiry by their own
  clock.
- **No owner powers.** A box session must not use the §2a device requests to revoke other
  devices or to rotate (`KEY_ADDED` with two sigs); only its own `KEY_REVOKED` is allowed. It
  must never submit `SignedLogEntry` kinds 3–7 or `OWNER_KEY_*`. The `sched/keylog.go:643` gate
  already covers owner powers; please also cover `rotateKey` / `selfRevoke` in `edge/keylog.go`.
- **CLI key authorized by a passkey (§4b).** `moochy owner init` on an account that only has
  passkeys:
  1. The CLI builds `entry::authorized_owner_key_body(ps, &pub, now, authorizer_ok_id)` and signs
     `sig_message(OwnerKeyAdded, body)` with the new key. It submits
     `SignedLogEntry{kind: "OWNER_KEY_ADDED", body, sigs: [new_sig]}`; `AppendSigned` cannot
     append it alone.
  2. The relay holds it as pending, bound to the session's pseudonym (Parse the body, check
     `Pseudonym` = the session user). It shows it on the web as "bind CLI owner key `ok_…` from
     device X?".
  3. The web runs one passkey `get()` (`allowCredentials` = the authorizer's credential) with
     `challenge = tlog.Challenge(tlog.SigMessage(tlog.OwnerKeyAdded, body))`.
  4. The relay calls `KeyLog.Append(ctx, tlog.OwnerKeyAdded, body,
     tlog.AuthorizedOwnerKeySig(newSig, assertion.Encode()))`.

  Append verifies both signatures, normalizes low-S and applies skew to `issued_at`. Answer the
  CLI's request with the index, or with the code (`owner_key_exists` if a CLI key already exists:
  rotate instead).

### 9b. mo-donor: mirror

- **Required patch.** `crates/node/src/keylog.rs`, `alert_fields`: checked, `cargo build -p moochy` and its tests build with these two arms.

  ```rust
  Alert::BoxEnrolled { idx, device_id, repo_id, box_id, expires_at_ms } => json!({"alert": "box_enrolled", "idx": idx, "kind": "KEY_ADDED", "device_id": clean(device_id), "repo_id": clean(repo_id), "box_id": clean(box_id), "expires_at_ms": expires_at_ms}),
  Alert::BoxOutsideRepo { idx, device_id, repo_id } => json!({"alert": "box_outside_repo", "idx": idx, "kind": "KEY_ADDED", "device_id": clean(device_id), "repo_id": clean(repo_id)}),
  ```

  `BoxEnrolled` is informational: show it in `moochy box list`, not as a security event.
  `BoxOutsideRepo` is a security event.
- **Expiry needs nothing from you.** `view.gateway_allowed` / `view.sealable` now refuse an
  expired box (`Code::Expired`) using the wall clock. `State::gateway_allowed_at(…, now_ms)` /
  `sealable_at` exist for tests. `Body::Key` has two new fields, `box_id` and `expires_at_ms`.
  Your patterns use `..`, so they are unaffected.
- **Listing.** `view.state(|s| s.boxes(&my_pseudonym))` returns `(device_id, &Device)` in log
  order. `Device.box_id` is `Some(bt_…)`, `expires_at_ms` is set, and `revoked` is set too: this
  is the `moochy box list` view from the log. Show "expired" when `now ≥ expires_at_ms`.
- **Box node itself.** A box runs `moochy up --headless` with `MOOCHY_ENROLL`. Its own mirror
  sees its own `KEY_ADDED` under the owner's pseudonym. Configure its `Me` with the box's own
  `sign_pub` in `known_keys` and do not treat the owner's other `BoxEnrolled` alerts as its
  business: a box should run the monitor for the gate only, without `Me`.
- **`moochy owner init` with passkeys** (§4b, 9a): when `Code::OwnerKeyExists` comes back from a
  first-key submission and the account has passkeys (`view.state(|s| s.owner_key(..))`), switch
  to the authorized form. Then `acknowledge_owner_key(pub)` as today, before submitting.

## 10. A224: a first CLI owner key needs a proof (spec/KEYLOG.md §4c)

From the cutover (2026-10-05T00:00:00Z, on the running max of the log's `logged_at`), the log
refuses a first CLI (Ed25519) owner key that carries no proof, with `owner_key_proof`. Before the
cutover the relay may still append the old proofless form, but it should stop now: wire the
proof, then a dev log can set `Config.OwnerKeyProofFromMs = 1` so tests exercise the rule today.

### 10a. mo-relay (append path) with mo-oauth (the confirmed link)

- **What the CLI sends is unchanged.** `moochy owner init` submits
  `SignedLogEntry{kind: "OWNER_KEY_ADDED", body: 4 fields (no prev), sigs: [new_sig]}`.
  `AppendSigned` would log it proofless. Instead, in `edge/keylog.go` `logEntry` route it like
  `holdOwnerKey` (`edge/pendingkey.go`) when all three hold:
  1. it is a first key (`prev` empty, no `Authorizer`);
  2. the user has no active owner key (`len(KeyLog.OwnerKeys(ps)) == 0`; with passkeys only:
     answer `owner_key_exists` and let the CLI use §4b);
  3. the session's pseudonym matches the body.

  Then check `new_sig` (`proto.Verify`, ZIP-215) and keep it pending, 10 min TTL, bound to the
  user, device and request id.
- **The confirmed link (mo-oauth + mo-notify).**
  1. Mail the account's **confirmed** address a single-use link naming the key:
     "bind CLI owner key `ok_…` from device X?". Store only `sha256(token)`.
  2. Refuse to mail when the confirmed address changed less than 72 h ago (`prefs.ChangedAt`, the
     same rule as the first passkey); answer the CLI `email_changed_recently`.
  3. Opening the link needs the user's web session (same user). Confirming with a POST, CSRF and
     same Origin, as for `/decide`, computes
     `proof := tlog.EmailProof(tokenHash, tlog.OwnerKeyID(pub), ps)` and calls
     `KeyLog.Append(ctx, tlog.OwnerKeyAdded, body, tlog.ProvenOwnerKeySig(newSig, proof))`.
  4. Answer the CLI's pending request with the index or the code.
- **Codes to surface:**
  - `owner_key_proof`: the old path was used after the cutover.
  - `owner_key_exists`: the account already has an owner key. Rotate a CLI key with `prev`; with
    passkeys only, use §4b.
  - `skew`: `issued_at` older than 10 min. The CLI signs at submit; if the click comes later,
    answer `skew` and let the CLI resubmit, or keep the pending TTL ≤ 10 min.
- **Tests.** In relay tests that bind owner keys through the Node path (`relay/test/keylog_test.go`,
  `decide_test.go`, e2e), set `Config.OwnerKeyProofFromMs = 1` once the flow exists, and confirm
  through the link. Until then they pass only before the cutover date.

### 10b. mo-donor (Node / CLI)

- **Required patch.** `crates/node/src/keylog.rs`, `alert_fields`: checked, `cargo build -p moochy` and its tests build with it.

  ```rust
  Alert::UnprovenOwnerKey { idx, owner_key, known } => json!({"alert": "unproven_owner_key", "idx": idx, "kind": "OWNER_KEY_ADDED", "owner_key": clean(owner_key), "known": known}),
  ```

  `known: true` is a reminder (log at info); `known: false` is a security event.
- **`moochy owner init` shows the proof state.** After submitting, print "waiting for you to
  confirm the email sent to your confirmed address (link names ok_…); expires in 10 min". On
  success, read `view.state(|s| s.owner_key(&id).map(|k| k.proof))` and show `OwnerKeyProof::Email`
  as "bound with your confirmed email" (or `Authorizer` as "authorized by your passkey").
  `moochy owner status` shows the same, and for `OwnerKeyProof::None` "bound before the email
  proof rule (on the relay's word); rotating keeps it trusted only if it was yours". Map the codes
  `owner_key_proof`, `owner_key_exists` and `email_changed_recently` to plain sentences.
- **Nothing else changes for verification.** The mirror applies the rule itself, with the
  compiled-in cutover. Legacy keys and their approvals stay valid.

## 11. Organisations (CONTRACT §19, spec/KEYLOG.md §2c)

New kinds: 13 `ORG_CLAIMED`, 14 `ORG_REPO_ADDED`, 15 `ORG_REPO_REMOVED`, all owner-signed (Ed25519
or passkey, like kinds 3–7). `DONOR_APPROVED` / `DONOR_REVOKED` may target an org id (`o_…`); the
id prefix tells the target. Existing logs and vectors verify unchanged. Vectors: `orgs.json`.

### 11a. mo-relay: append path, gate, pool

- **Bodies.** `tlog.OrgClaim{OrgID, Provider, ProviderOrgID /* numeric provider id */, Owner,
  Signer, IssuedAtMs}.Body()`, `tlog.OrgRepo{OrgID, RepoID, Signer, IssuedAtMs}.Body()`, and
  `tlog.Grant{RepoID: orgID, Subject: donor, …}` for an org approval. `Parse()` returns
  `tlog.OrgClaim` / `tlog.OrgRepo` (new types: your `case tlog.Claim` / `tlog.Grant` arms do not
  see org claims). `KindByName` knows the three names. `Kind.OwnerSigned()` is exported: use it
  instead of `k >= RepoClaimed && k <= MemberRemoved` in `edge/keylog.go` (A180 gate) and
  `edge/decide.go` (passkey kinds), once the gate below handles them.
- **Fail closed today.** `AppendSigned` refuses kinds 13–15 with `ungated`, so nothing enters the
  log through the link before your §19 gate exists. After your gate admits an entry, append it with
  `klog.Append(ctx, k, body, sig)` (skew, signature, state rules run there as usual).
- **Gate (`sched/keylog.go`, `logGate`), mirror of the repo rules:**
  - `ORG_CLAIMED`: `Owner` is this user, and a fresh single-use provider check says they own the
    org (GitHub membership `admin` with `read:org`, GitLab access level Owner), with `Provider` /
    `ProviderOrgID` equal to the org row. Assign the `o_` id once per (provider, provider org id)
    and never reuse it; a personal account is never an org.
  - `ORG_REPO_ADDED`: the org's current owner is this user, the repo is claimed by this user too,
    and the provider says the repo belongs to the org (repo owner id = org id; GitLab: the repo's
    namespace is the group or a subgroup). The log enforces the same-owner rule itself
    (`not_owner`); the provider check is yours. `ORG_REPO_REMOVED`: the org's owner only.
  - `DONOR_*` on an `o_` id: the org's current owner. Today `s.repos[o_…]` is nil, so they are
    refused with `not_owner` (fail closed) until you add the org lookup.
  - Signer is one of `KeyLog.OwnerKeys(ps)`, as for repos.
- **Codes:** `not_owner` (repo claimed by someone else, or not the org owner's key), `unclaimed`
  (org or repo not claimed), `replay`, `repo_binding` (org re-claimed with another provider id),
  `skew`, `bad_sig`, `ungated`.
- **Pool / `PoolSync`.** `klog.Sealable(worker, repo)` already answers the org rule (repo approval,
  else an org that covers the repo with both claims under the same owner). `approvalIdx` is the
  repo's own approval when active, else the **smallest** index among covering orgs' approvals: put
  exactly that in `approval_log_index` (the Gateway compares it), even when another org's donation
  pays. `klog.Owner(o_…)` returns the org owner. `klog.Sealable(w, "o_…")` is `unclaimed`.
- **Listings.** Activity/admin walkers: kinds 13–15 parse to the new types; show `ORG_*` with the
  org slug from your DB (slugs never enter the log).

### 11b. mo-donor: node gate and alerts

- **Sealing gate: nothing to call.** `View::seal_check` / `State::sealable` apply the org rule and
  return the same `approval_idx` as the relay's `Sealable`; `check_pool_worker` compares it
  unchanged. Errors stay `not_approved` / `unclaimed`.
- **Alerts: no new variant, no patch to `alert_fields`.** Org entries reuse
  `Alert::NotSignedByMe { kind: ORG_CLAIMED | ORG_REPO_ADDED | ORG_REPO_REMOVED | DONOR_*, repo_id:
  "o_…" }` (an org entry on my org, or an org claim naming me, signed by an owner key I do not
  know) and `Alert::RepoClaimedByOther { repo_id: "o_…" }` (my org claimed by another account).
  `repo_id` starting with `o_` means organisation; the monitor's message already says "your
  organisation o_…". If the UI shows slugs, resolve `o_` ids like repo ids.
- **Approvals on the CLI (`approve.rs`, `owner.rs`).** `parse_body` returns `Body::OrgClaim
  { org_id, provider, provider_org_id, owner, signer, issued_at_ms }` and `Body::OrgRepo { org_id,
  repo_id, signer, issued_at_ms }`; bodies to sign: `entry::org_claim_body`, `entry::org_repo_body`,
  `entry::grant_body(org_id, donor, …)`. To offer them, add `ORG_CLAIMED` 13, `ORG_REPO_ADDED` 14,
  `ORG_REPO_REMOVED` 15 to `kind_num`, and map the new bodies in `decode` / the sign handler (a
  claim names this account as `owner`; `--org github/acme` resolves to the `o_` id and must equal
  the request's). Until then the existing `_ =>` arms refuse them (fail closed). Nodes submit
  org entries over the link like other owner-signed kinds; the relay answers `ungated` until its
  gate (11a) exists.
- **A265: nothing signed before the current owner's claim.** Each repo and org remembers the
  `issued_at` of the claim that set its current owner (a same-owner re-claim keeps it). Any
  `DONOR_*`, `MEMBER_*` or `ORG_REPO_*` with `issued_at` at or before it is `replay`, and so is an
  `ORG_REPO_ADDED` issued at or before the repo's own owner claim. A round trip A→E→A therefore
  never revives a revoked approval or a removed repo, even if the relay replays A's old signatures.
  **mo-relay:** after an owner change (a takeover, or the owner re-claiming after one), drop every
  pending `ApprovalRequest` body built before it and push fresh ones; A must re-sign approvals and
  "add all". Build every `body_to_sign` for `DONOR_*`/`MEMBER_*`/`ORG_REPO_*` with `IssuedAtMs =
  max(now, issued_at of the current claim + 1)`: the claim's `issued_at` comes from the owner's
  clock (up to `MaxSkew` ahead of the relay's), and a body built in the same millisecond is refused.
  `klog.OwnerSinceMs(id)` returns that `issued_at`. Nodes need nothing: `State::apply` enforces it.
- **A269 note: is the donor really approved on the org?** `view.state(|s| s.donor_approved(org_id,
  &donor_pseudonym))` (also works on an `r_…` id): `true` only for an active `DONOR_APPROVED` signed
  by the target's **current** owner; one from before a takeover, a revoked one, or an unclaimed
  target answers `false`. Go: `klog.DonorApproved(target, ps)`.
- **`moochy owner status`: the orgs I own.** `view.state(|s| s.owned_orgs(&me))` →
  `Vec<(org_id, Vec<repo_id>)>`, sorted by id: each org this account owns and the repos it covers
  (active `ORG_REPO_ADDED`, repo claimed by the same owner: exactly the repos its donations serve).
  Resolve ids to slugs like repo ids. After a takeover (§19.2) the org leaves the old owner's list;
  the new owner's starts with no repos until they re-add them (and re-approve donors).
- **Mac.** `moochy-keylog` cannot be cross-checked here (ring); the integrator's Mac build covers it.

## 12. People (CONTRACT §24, spec/KEYLOG.md §2d)

New kinds: 16 `PERSON_CLAIMED`, 17 `PERSON_REPO_ADDED`, 18 `PERSON_REPO_REMOVED`, all owner-signed
(Ed25519 or passkey). `DONOR_APPROVED` / `DONOR_REVOKED` may target a person id (`m_…`). Existing
logs and vectors verify unchanged. Vectors: `people.json`.

### 12a. mo-people (relay): append path, gate, pool

- **Bodies.** `tlog.PersonClaim{PersonID, Provider, ProviderUserID /* numeric provider user id */,
  Owner, Signer, IssuedAtMs}.Body()`, `tlog.PersonRepo{PersonID, RepoID, Signer, IssuedAtMs}.Body()`,
  `tlog.Grant{RepoID: personID, Subject: donor, …}` for a sponsor approval. `Parse()` returns the
  new types (never `OrgClaim` / `OrgRepo`). `KindByName` knows the names; `Kind.OwnerSigned()` is
  true for 16–18.
- **Fail closed.** `AppendSigned` refuses kinds 16–18 with `ungated`; after your gate (`Owner` is
  this user and signed in **as** that provider user id; repo public with a maintainer role for
  `PERSON_REPO_ADDED`) append with `klog.Append` (skew, signature, state rules run there).
- **Log rules you can rely on.** A `PERSON_CLAIMED` naming another owner than the person's current
  one is `already_claimed` (never a takeover); the same `(provider, provider_user_id)` under a
  second `m_` id is `repo_binding` (allocate one `m_` per provider user, never reuse it);
  `PERSON_REPO_*` need the person's owner key (`not_owner`), the person claimed (`unclaimed`), and
  `issued_at` after the claim and after the previous entry for (person, repo) (`replay`). The repo
  need not be claimed. Build bodies with `IssuedAtMs = max(now, OwnerSinceMs(m_…)+1)`.
- **Pool / `PoolSync`.** For a person donation's worker use `klog.PersonSealable(worker, repo,
  gateway)` (the person rule alone, as the donor's Node checks it). `dev, approvalIdx, err :=
  klog.SealableFor(worker, repo, gateway)`: exactly
  `Sealable(worker, repo)` when that allows; else the person path (gateway device = a logged,
  unrevoked, unexpired gateway of the pseudonym owning a person M that covers `repo` and approved the
  worker's donor) with the **smallest** such approval index. Put it in `approval_log_index`.
  `klog.Owner(m_…)`, `OwnerSinceMs(m_…)`, `DonorApproved(m_…, ps)` answer for people;
  `klog.OwnedPeople(ps)` → person id → covered repo ids (sorted), for `moochy person list`.
- **Submit.** `GatewayAllowed` is unchanged (a person never spends the repo's or its orgs'
  donations through it). For a person donation, accept the requester with
  `klog.PersonGatewayAllowed(gateway, repo)`: a logged, unrevoked, unexpired gateway device (scope
  allowing the repo) of the owner of a person covering the repo (`not_member` otherwise), and route
  it **only** to that person's donations.

### 12b. mo-donor: node gate and alerts

- **Sealing gate.** `view.state(|s| s.person_sealable(worker, repo, gateway))` (and `_at(…, now_ms)`):
  the person rule **alone** (a repo/org approval never satisfies it, and it never satisfies
  `sealable`), `Sealable { enc_pub, key_idx, approval_idx }` with the smallest person approval index.
  Gateway side: `gateway` = this Node's own device id; compare `key_idx` / `approval_idx` with
  `PoolWorker` yourself and keep the `View::gate` check. Worker side, for a person pledge: `gateway` =
  the task's gateway device, then verify the task signature with that device's `sign_pub`.
  `s.sealable_for(worker, repo, gateway)` = `sealable` when it allows, else `person_sealable` (what
  the relay's `SealableFor` answers). Errors: `not_approved` (another member of the repo, a device
  of another account, an uncovered repo, an unapproved sponsor), `unclaimed` (not an `r_` id),
  device codes for either device.
- **Alerts: no new variant.** `Alert::NotSignedByMe { kind: PERSON_* | DONOR_*, repo_id: "m_…" }`
  for a person claim naming me, or an entry on my person, signed by an owner key I do not know;
  the message says "your person profile m_…". A takeover cannot happen (refused, `Rejected` alert).
- **CLI.** `parse_body` returns `Body::PersonClaim { person_id, provider, provider_user_id, owner,
  signer, issued_at_ms }` and `Body::PersonRepo { person_id, repo_id, signer, issued_at_ms }`;
  builders `entry::person_claim_body`, `entry::person_repo_body`, `entry::grant_body(person_id, …)`;
  `Kind::from_name` knows the names (add 16–18 to `kind_num`). `view.state(|s| s.owned_people(&me))`
  → `Vec<(person_id, Vec<repo_id>)>` sorted, for `moochy person list` / `owner status`.
- **Mac.** `moochy-keylog` cannot be cross-checked here (ring); the integrator's Mac build covers it.
