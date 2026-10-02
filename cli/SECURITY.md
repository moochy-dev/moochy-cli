# Security policy

This policy covers the open-source Moochy client (Apache-2.0): the `moochy` app, its protocol, and its sandbox.

## Reporting a vulnerability

Email **security@moochy.dev**. Please do not open a public issue, pull request, or discussion for a security problem.

Include what you can:

- the version (`moochy --version`, or the commit) and your operating system;
- what an attacker can do, and what they need first (a donor account, a malicious relay, a local user, a crafted request or response, …);
- steps to reproduce, or a proof of concept;
- whether you want to be credited, and under which name.

If you need to send something sensitive and would like an encryption key first, ask in your first email.

## Scope

In scope:

| Area | Examples |
|---|---|
| **The client** (`cli/`) | The `moochy` app in both roles: the background process, the local API and MCP endpoints, the command-line app, the keystore, key-log verification, provider adapters, safety checks, tool-call checks, response re-emission |
| **The protocol** (`spec/protocol.md`, `spec/KEYLOG.md`, `spec/proto/`, `spec/vectors/`) | Weaknesses in the encryption, signatures, key derivations, receipts, key log, or receipt log; places where the spec and the vectors disagree |
| **The sandbox** (`cli/crates/sandbox`) | Escapes from `moochy run` on Linux or macOS (reading files outside the project, reaching the network beyond Moochy and allowed hosts, outliving the run, affecting the host through git metadata); weaknesses in the donor-side lockdown or the per-request validator |
| **Release integrity** (`deploy/client/`) | Problems with signatures, provenance, or reproducible builds of the client |

Our design assumes the relay may be malicious. If a relay, or anyone who controls one, can read a prompt, forge or replay a request, spend more than a donor's own limits, get a donor accepted without the owner's signature, or deliver bytes the client accepts as genuine, that is a client or protocol vulnerability, and in scope.

Out of scope here:

- The moochy.dev website and the relay service themselves (closed source). Report problems you notice there to the same address; we handle them, but they are not covered by the promises below.
- Problems that need an attacker already running code as your user outside the sandbox, or root on your machine.
- A donor returning wrong or low-quality answers: that is a quality problem, handled by receipts, disputes, and the owner choosing donors.
- Vulnerabilities in a provider's API or in a local model server, unless the client makes them worse.
- Denial of service that needs unrealistic volume, and findings from automated scanners without a working impact.

## What we promise

- **Acknowledge** your report within **3 working days**, with a person's reply, not an autoresponder.
- **Assess** it and tell you what we think within **10 working days**: severity, whether we can reproduce it, and our plan.
- **Fix** it within these targets, counted from when we confirm it:

  | Severity | Target |
  |---|---|
  | Critical (key or prompt disclosure, remote code execution, sandbox escape, spending beyond a donor's limits) | 7 days |
  | High | 30 days |
  | Medium | 90 days |
  | Low | Next regular release |

  If we cannot meet a target, we tell you why and when we expect to.
- **Keep you informed** until it is fixed, and let you check the fix before release when you want to.
- **Credit** you in the release notes and the advisory, unless you prefer not to be named.
- **Publish** a security advisory for every fixed vulnerability of medium severity or higher, with the affected and fixed versions.

We ask that you give us until the fix is released, or 90 days from your report, whichever comes first, before you publish details. We will agree to a shorter or longer timeline with you when the situation calls for it.

## Safe harbour

We will not take legal action against you, or ask anyone else to, for security research on the Moochy client and protocol that follows this policy in good faith. That means:

- you test only against your own accounts, devices, keys, and projects, or with the explicit permission of their owners;
- you do not access, change, or keep other people's data beyond the minimum needed to show the problem, and you delete it afterwards;
- you do not spend other people's donations or provider credit, degrade the service for others, or use social engineering, phishing, or physical attacks;
- you report the problem to us privately and give us reasonable time to fix it.

If your research follows these rules, we consider it authorised, we will not treat it as a violation of our terms, and we will say so publicly if anyone asks. If you are unsure whether something is covered, ask us first.

The relay service and the moochy.dev website are not covered by this safe harbour: do not test against them beyond normal use of your own account. Report what you notice and we will work with you.

## How Moochy is built to resist attacks

A public summary of the threats we design against, and where in the open client each defence lives: [`docs/guides/threat-model.md`](../docs/guides/threat-model.md). The protocol is specified in [`spec/protocol.md`](../spec/protocol.md) and [`spec/KEYLOG.md`](../spec/KEYLOG.md).

## Supported versions

Security fixes go into the latest release. Update with a signed release (`moochy update --from-file <file>`, which refuses unsigned files). Check a release yourself with `gh attestation verify <file> --repo moochy-dev/moochy-cli`.
