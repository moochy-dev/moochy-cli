# moochy-keylog

The client side of the Moochy key log: the public, append-only log of device keys, owner keys,
claims and accepted donors. A Moochy app trusts what this log proves, never the relay's word.

- `merkle`: RFC 6962/9162 hashing, inclusion and consistency proofs.
- `note` and `cosig`: signed checkpoints (C2SP tlog-checkpoint, Ed25519) and witness cosignatures.
- `entry`: the exact record formats. `webauthn` handles passkey owner keys (ES256).
- `state`: the authority state machine, which answers "may this device seal for project R?" and
  "may this gateway use project R?".
- `tiles`, `mirror`, `monitor`: C2SP tlog-tiles, a full incremental mirror, and monitor rules that
  warn about owner actions you did not sign and about forks. Gateways and Workers share one
  fail-closed view.
- `receipts`, `projection`: receipt-log inclusion and `moochy verify` of donor-signed receipts.
- `fetch` (feature `http`): a bounded tile fetcher with size limits and timeouts.

Format: `spec/KEYLOG.md` in [moochy-docs](https://github.com/moochy-dev/moochy-docs). Test:
`cargo test -p moochy-keylog`. License: Apache-2.0.
