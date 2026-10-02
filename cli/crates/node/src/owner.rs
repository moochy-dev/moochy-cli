//! Owner key (CONTRACT §15.4, spec/KEYLOG.md §4): a separate Ed25519 key, encrypted at rest,
//! decrypted only by the foreground CLI for one approval / membership / claim after the human
//! confirmed what it signs, and dropped right after. The background Node never reads the secret;
//! it knows only the public halves (`<state>/owner_keys`, for the monitor's owner alerts) and
//! relays the signed entry (`SubmitEntry`).
//!
//! Passphrase: `MOOCHY_OWNER_PASSPHRASE` (headless, CI) or typed on the terminal (never stdin, so
//! a tool piping into `moochy` cannot answer). It is deliberately not the keystore passphrase:
//! the background process runs with that one.

use crate::config::Home;
use crate::pb::local::{ApproveRequest, ClaimRequest, MembersRequest, SignResponse, SubmitEntryRequest, members_request::Op};
use crate::util::{Ctx as _, Result, auth, b64e, clean, internal, now_ms, usage};
use moochy_keylog::Kind;
use moochy_keylog::entry::{Body, claim_body, grant_body, owner_key_body, owner_key_id, parse_body, sig_message};
use moochy_proto::crypto::SignKey;
use serde_json::json;
use std::io::{BufRead as _, Write as _};
use zeroize::Zeroizing;

const AAD: &[u8] = b"moochy/owner-key/v1";

fn key_path(home: &Home, relay: Option<&str>) -> std::path::PathBuf {
    home.keystore_path(relay).with_extension("owner")
}

/// The terminal, for prompts nobody can pipe into.
fn tty() -> Result<std::fs::File> {
    std::fs::OpenOptions::new().read(true).write(true).open("/dev/tty").map_err(|_| usage("no terminal: owner approvals need a person (or MOOCHY_OWNER_PASSPHRASE with --yes for CI)"))
}

fn stty(t: &std::fs::File, arg: &str) {
    // A190: no inherited environment (passphrases) in children.
    if let Ok(f) = t.try_clone() {
        let _ = std::process::Command::new("stty").arg(arg).stdin(f).env_clear().env("PATH", "/usr/bin:/bin").status();
    }
}

fn ask(prompt: &str, hidden: bool) -> Result<Zeroizing<String>> {
    let mut t = tty()?;
    let _ = write!(t, "{prompt}");
    if hidden {
        stty(&t, "-echo");
    }
    let mut line = Zeroizing::new(String::new());
    let r = std::io::BufReader::new(t.try_clone().ctx("terminal")?).read_line(&mut line);
    if hidden {
        stty(&t, "echo");
        let _ = writeln!(t);
    }
    r.ctx("terminal")?;
    let trimmed = Zeroizing::new(line.trim_end_matches(['\r', '\n']).to_owned());
    Ok(trimmed)
}

fn passphrase(new: bool) -> Result<Zeroizing<String>> {
    let env = |k: &str| std::env::var(k).ok().map(Zeroizing::new).filter(|p| !p.is_empty());
    if let Some(p) = env("MOOCHY_OWNER_PASSPHRASE") {
        return Ok(p);
    }
    // Tests and development only: the keystore passphrase stands in when there is no terminal.
    if std::env::var("MOOCHY_INSECURE_DEV").as_deref() == Ok("1") && tty().is_err()
        && let Some(p) = env("MOOCHY_PASSPHRASE")
    {
        eprintln!("moochy: WARNING owner key protected by the keystore passphrase (MOOCHY_INSECURE_DEV only)");
        return Ok(p);
    }
    let p = ask("Owner key passphrase: ", true)?;
    if new {
        if p.chars().count() < 8 {
            return Err(usage("use at least 8 characters for the owner key passphrase"));
        }
        if *ask("Repeat it: ", true)? != *p {
            return Err(usage("the passphrases differ"));
        }
    }
    Ok(p)
}

/// Decrypt the owner key (only after the user confirmed).
fn load(home: &Home, relay: Option<&str>) -> Result<SignKey> {
    let file = std::fs::read(key_path(home, relay)).map_err(|_| usage("no owner key on this device: run `moochy owner init` first"))?;
    let seed = crate::keystore::open(&file, &passphrase(false)?, AAD)?;
    let seed = Zeroizing::new(<[u8; 32]>::try_from(seed.as_slice()).map_err(|_| auth("owner key file is corrupt"))?);
    Ok(SignKey::from_seed(&seed))
}

fn store(home: &Home, relay: Option<&str>, key: &SignKey, pass: &str) -> Result<()> {
    let sealed = crate::keystore::seal(key.seed().as_ref(), pass, AAD)?;
    crate::config::write_private(&key_path(home, relay), &sealed)?;
    let path = home.state_dir().join("owner_keys");
    let mut all = std::fs::read_to_string(&path).unwrap_or_default();
    all.push_str(&b64e(&key.public()));
    all.push('\n');
    crate::config::write_private(&path, all.as_bytes())
}

fn rt() -> Result<tokio::runtime::Runtime> {
    tokio::runtime::Builder::new_current_thread().enable_all().build().ctx("runtime")
}

fn status(s: &tonic::Status) -> crate::util::Error {
    match s.code() {
        tonic::Code::NotFound | tonic::Code::FailedPrecondition | tonic::Code::InvalidArgument => usage(clean(s.message()).into_owned()),
        tonic::Code::Unavailable | tonic::Code::DeadlineExceeded => crate::util::net(clean(s.message()).into_owned()),
        _ => internal(clean(s.message()).into_owned()),
    }
}

async fn submit(home: &Home, req: SubmitEntryRequest) -> Result<SignResponse> {
    let mut c = crate::ctl::connect(&home.socket_path()).await?;
    c.submit_entry(req).await.map(tonic::Response::into_inner).map_err(|s| status(&s))
}

/// Create an owner key, register it in the key log (OWNER_KEY_ADDED, signed by the new key and,
/// on rotation, by `prev`), and keep it encrypted only once the log accepted it.
fn register(home: &Home, rt: &tokio::runtime::Runtime, prev: Option<&SignKey>) -> Result<SignKey> {
    let cfg = home.load()?;
    let pseudonym = cfg.pseudonym.clone().ok_or_else(|| auth("not logged in: run `moochy login` first"))?;
    let new = SignKey::from_seed(&Zeroizing::new(crate::util::rand_bytes::<32>()?));
    let pass = passphrase(true)?;
    let body = owner_key_body(&pseudonym, &new.public(), prev.map(SignKey::public).as_ref(), now_ms());
    let msg = sig_message(Kind::OwnerKeyAdded, &body);
    let mut sigs = vec![new.sign(&msg).to_vec()];
    sigs.extend(prev.map(|p| p.sign(&msg).to_vec()));
    let r = rt.block_on(submit(home, SubmitEntryRequest { request_id: String::new(), kind: "OWNER_KEY_ADDED".into(), body, sigs }))?;
    store(home, cfg.relay.as_deref(), &new, &pass)?;
    crate::util::emit(&json!({"event": if prev.is_some() { "owner_key_rotated" } else { "owner_key_added" }, "owner_key": owner_key_id(&new.public()), "log_index": r.log_index}));
    Ok(new)
}

/// `moochy owner init` (first key) / `moochy owner rotate` (new key, the current one signs too).
pub fn init(home: &Home, rotate: bool) -> Result<()> {
    let cfg = home.load()?;
    let relay = cfg.relay.as_deref();
    let prev = if rotate {
        Some(load(home, relay)?)
    } else {
        if key_path(home, relay).exists() {
            return Err(usage("this device already has an owner key (`moochy owner rotate` replaces it)"));
        }
        None
    };
    register(home, &rt()?, prev.as_ref()).map(drop)
}

/// What the command asked to sign. Every entry the owner key signs is bound to it (A217/A218):
/// the background process (or anything on `node.sock`) only proposes; the CLI decides.
#[derive(Clone, Copy, Debug)]
struct Ask<'a> {
    kind: Kind,
    repo_slug: &'a str,
    /// The user argument: a handle, a pseudonym, or a device id (`members --device`).
    subject: Option<&'a str>,
    /// `members --device`: the argument is a device id, shown as the label; the body names the
    /// device owner's pseudonym (E32).
    device: bool,
}

/// The exact fields one signature will cover, after binding.
#[derive(Debug, PartialEq, Eq)]
struct Bound {
    kind: Kind,
    repo_id: String,
    /// Grants: the subject pseudonym / device id. Claims: the owner (this account).
    subject: String,
    /// Claims only: provider and provider repo id from the claim request.
    claim: Option<(String, String)>,
}

/// Check one previewed entry against the command and this account; `Err` = never sign it.
/// Labels (`repo_slug`, `subject_username`) are not signature-covered, so they must match the
/// arguments, and the body the relay proposed must agree with the fields shown.
fn bind(ask: &Ask<'_>, me: Option<&str>, p: &SignResponse) -> Result<Bound> {
    let refuse = |what: &str| usage(format!("refusing to sign: the app proposed {what}, not what you asked for"));
    let kind = Kind::from_name(&p.kind).ok_or_else(|| refuse("an unknown entry kind"))?;
    if kind != ask.kind {
        return Err(refuse(&format!("{} instead of {}", kind.name(), ask.kind.name())));
    }
    if !p.repo_slug.eq_ignore_ascii_case(ask.repo_slug) {
        return Err(refuse(&format!("project {}", clean(&p.repo_slug))));
    }
    match (parse_body(kind, &p.body_to_sign), ask.subject) {
        (Ok(Body::Claim { repo_id, provider, provider_repo_id, owner, .. }), None) => {
            if repo_id != p.repo_id || me != Some(owner) || p.subject != owner {
                return Err(refuse("a claim naming another account or project"));
            }
            Ok(Bound { kind, repo_id: repo_id.into(), subject: owner.into(), claim: Some((provider.into(), provider_repo_id.into())) })
        }
        (Ok(Body::Grant { repo_id, subject, .. }), Some(arg)) => {
            if repo_id != p.repo_id || subject != p.subject {
                return Err(refuse("a body that differs from what it shows"));
            }
            // Device ids and pseudonyms are matched exactly; a handle against the label.
            let ok = arg == subject
                || (!arg.starts_with("d_") && !arg.starts_with("ps_") && arg.eq_ignore_ascii_case(&p.subject_username))
                || (ask.device && arg.starts_with("d_") && arg == p.subject_username && subject.starts_with("ps_"));
            if !ok {
                return Err(refuse(&format!("subject {} ({})", clean(&p.subject_username), clean(subject))));
            }
            Ok(Bound { kind, repo_id: repo_id.into(), subject: subject.into(), claim: None })
        }
        _ => Err(refuse("a malformed entry")),
    }
}

/// Show every signed field of one entry and ask (A217): `--yes` skips only the question.
fn confirm(b: &Bound, p: &SignResponse, signer: &str, extra: &str, yes: bool) -> Result<()> {
    let meaning = match b.kind {
        Kind::DonorApproved => "may donate tokens to (and see the requests of)",
        Kind::DonorRevoked => "may no longer donate to",
        Kind::MemberAdded => "may use the donated tokens of",
        Kind::MemberRemoved => "may no longer use the donated tokens of",
        _ => "is the owner of",
    };
    eprintln!("Owner signature {}:", b.kind.name());
    eprintln!("  {} ({}) {meaning} {} ({})", clean(&p.subject_username), clean(&b.subject), clean(&p.repo_slug), clean(&b.repo_id));
    if let Some((prov, id)) = &b.claim {
        eprintln!("  project at {} (id {})", clean(prov), clean(id));
    }
    eprintln!("  signed by your owner key {signer}{extra}");
    if !yes && !matches!(ask("Type yes to sign: ", false)?.as_str(), "yes" | "y") {
        return Err(usage("not signed"));
    }
    Ok(())
}

/// Build the owner-signed body from the BOUND fields only and hand it to the Node.
fn sign_one(home: &Home, rt: &tokio::runtime::Runtime, key: &SignKey, b: &Bound, p: &SignResponse) -> Result<SignResponse> {
    let signer = owner_key_id(&key.public());
    let now = now_ms();
    let body = match &b.claim {
        Some((provider, provider_repo_id)) => claim_body(&b.repo_id, provider, provider_repo_id, &b.subject, &signer, now),
        None => grant_body(&b.repo_id, &b.subject, &signer, now),
    };
    let sig = key.sign(&sig_message(b.kind, &body));
    rt.block_on(submit(home, SubmitEntryRequest { request_id: p.request_id.clone(), kind: b.kind.name().into(), body, sigs: vec![sig.to_vec()] }))
}

fn emit_signed(done: &SignResponse) {
    crate::util::emit(&json!({"request_id": done.request_id, "kind": done.kind, "repo": done.repo_slug, "repo_id": done.repo_id, "subject": done.subject,
        "subject_username": done.subject_username, "signer": done.signer, "issued_at_ms": done.issued_at_ms, "signed": done.signed, "log_index": done.log_index}));
}

/// `moochy approve|members|claim`: preview what the relay asks, show it, get an explicit yes and
/// the owner passphrase, rebuild the body with the owner key id and the current time
/// (KEYLOG §5), sign, and hand the entry to the Node to relay.
#[allow(clippy::too_many_arguments, clippy::fn_params_excessive_bools)]
pub fn sign(home: &Home, slug: &str, words: &[&str], yes: bool, revoke: bool, device: bool, cap: i64) -> Result<()> {
    let cfg = home.load()?;
    let rt = rt()?;
    let preview = rt.block_on(async {
        let mut c = crate::ctl::connect(&home.socket_path()).await?;
        let r = match words {
            ["approve", donor] => c.approve(ApproveRequest { repo: slug.into(), donor: (*donor).into(), dry_run: true, revoke }).await,
            ["members", op, user] => {
                let op = if *op == "add" { Op::Add } else { Op::Remove };
                c.members(MembersRequest { repo: slug.into(), op: op as i32, user: (*user).into(), cap_uusd_month: cap, device, dry_run: true }).await
            }
            _ => c.claim(ClaimRequest { repo: slug.into(), dry_run: true }).await,
        };
        r.map(tonic::Response::into_inner).map_err(|s| status(&s))
    })?;
    let want = match words {
        ["approve", donor] => Ask { kind: if revoke { Kind::DonorRevoked } else { Kind::DonorApproved }, repo_slug: slug, subject: Some(donor), device: false },
        ["members", op, user] => Ask { kind: if *op == "add" { Kind::MemberAdded } else { Kind::MemberRemoved }, repo_slug: slug, subject: Some(user), device },
        _ => Ask { kind: Kind::RepoClaimed, repo_slug: slug, subject: None, device: false },
    };
    let me = cfg.pseudonym.as_deref();
    let main = bind(&want, me, &preview)?;
    // An approval needs an owner-signed claim of the same project naming this account
    // (KEYLOG §5): offered as its own entry, shown in full, confirmed on its own.
    let claim = (want.kind != Kind::RepoClaimed)
        .then(|| rt.block_on(async {
            let mut c = crate::ctl::connect(&home.socket_path()).await.ok()?;
            c.claim(ClaimRequest { repo: slug.into(), dry_run: true }).await.ok().map(tonic::Response::into_inner)
        }))
        .flatten()
        .and_then(|p| bind(&Ask { kind: Kind::RepoClaimed, repo_slug: slug, subject: None, device: false }, me, &p).ok().filter(|b| b.repo_id == main.repo_id).map(|b| (b, p)));
    let has_key = key_path(home, cfg.relay.as_deref()).exists();
    if !has_key {
        eprintln!("No owner key yet: one will be created (a separate key with its own passphrase) and registered in the public key log.");
        if !yes && !matches!(ask("Type yes to create it: ", false)?.as_str(), "yes" | "y") {
            return Err(usage("nothing signed"));
        }
    }
    let signer = if has_key { "(existing)".to_owned() } else { "(new)".to_owned() };
    if let Some((b, p)) = &claim {
        confirm(b, p, &signer, "", yes)?;
    }
    let extra = if want.kind == Kind::MemberAdded && cap > 0 { format!("; monthly limit {} (a project setting, not signed)", crate::util::fmt_dollars(u64::try_from(cap).unwrap_or(0))) } else { String::new() };
    confirm(&main, &preview, &signer, &extra, yes)?;
    let key = if has_key { load(home, cfg.relay.as_deref())? } else { register(home, &rt, None)? };
    if let Some((b, p)) = &claim {
        emit_signed(&sign_one(home, &rt, &key, b, p)?);
    }
    let done = sign_one(home, &rt, &key, &main, &preview)?;
    drop(key);
    emit_signed(&done);
    Ok(())
}

/// `moochy keys rotate` (06 §4, E73): a new device key pair under a new device id, logged as a
/// KEY_ADDED signed by the new key (proof of possession) and by the current device key over
/// `lp("moochy/v1/key-rotate", body)`. The relay revokes the old key after a 24 h grace; the
/// running app keeps its session until it restarts with the new key.
pub fn rotate_device(home: &Home) -> Result<()> {
    use crate::keystore::{self, DeviceKeys};
    let mut cfg = home.load()?;
    let mut sec = keystore::load(home, &cfg)?.ok_or_else(|| auth("no keystore: run `moochy login` first"))?;
    let old = sec.device.as_ref().ok_or_else(|| auth("not logged in: run `moochy login` first"))?.sign_key();
    let pseudonym = cfg.pseudonym.clone().ok_or_else(|| auth("not logged in: run `moochy login` first"))?;
    let new = DeviceKeys::generate()?;
    let (sign_pub, enc_pub) = (new.sign_key().public(), new.enc_key()?.public());
    let id = format!("d_{}", crate::util::ulid()?);
    let roles = match (cfg.has_role("gateway"), cfg.has_role("worker")) {
        (true, true) => "gateway,worker",
        (false, true) => "worker",
        _ => "gateway",
    };
    // ponytail: repo-scoped (CI) devices keep their scope only once it is read back from the log;
    // the relay refuses a scope change (subject_mismatch) rather than widening it.
    let suite = crate::login::SUITE;
    let body = moochy_keylog::entry::key_body(&id, &pseudonym, &sign_pub, &enc_pub, suite, roles, "");
    let pop = new.sign_key().sign(&moochy_keylog::entry::pop_message(&sign_pub, &enc_pub, suite));
    let endorse = old.sign(&moochy_keylog::entry::rotate_request_message(&body));
    let r = rt()?.block_on(submit(home, SubmitEntryRequest { request_id: format!("rotate-{id}"), kind: "KEY_ADDED".into(), body, sigs: vec![pop.to_vec(), endorse.to_vec()] }))?;
    sec.device = Some(new);
    keystore::save(home, &cfg, &sec)?;
    cfg.device_id = Some(id.clone());
    home.save(&cfg)?;
    crate::util::emit(&json!({"event": "key_rotated", "device_id": id, "log_index": r.log_index, "note": "restart the app (`moochy down && moochy up`) within 24 h to use the new key"}));
    Ok(())
}

/// `moochy keys revoke <device_id>` (the own-key alert's advice, T-06-083): revoke ANOTHER device
/// of this account, e.g. one the key log shows but you never added. Signed by this device
/// (KEYLOG §2a revoke request), relayed by the running app; this device: `moochy logout`.
pub fn revoke_device(home: &Home, device_id: &str) -> Result<()> {
    let cfg = home.load()?;
    if Some(device_id) == cfg.device_id.as_deref() {
        return Err(usage("that is this device: use `moochy logout`"));
    }
    if !moochy_keylog::entry::is_id(device_id, "d_") {
        return Err(usage("keys revoke <device id> (d_…, as shown in the alert or on the Devices page)"));
    }
    let pseudonym = cfg.pseudonym.clone().ok_or_else(|| auth("not logged in: run `moochy login` first"))?;
    let sec = crate::keystore::load(home, &cfg)?.ok_or_else(|| auth("no keystore: run `moochy login` first"))?;
    let me = sec.device.as_ref().ok_or_else(|| auth("not logged in: run `moochy login` first"))?.sign_key();
    let body = moochy_keylog::entry::revoke_body(device_id, &pseudonym, "user");
    let sig = me.sign(&moochy_keylog::entry::revoke_request_message(&body));
    let r = rt()?.block_on(submit(home, SubmitEntryRequest { request_id: format!("revoke-{device_id}"), kind: "KEY_REVOKED".into(), body, sigs: vec![sig.to_vec()] }))?;
    crate::util::emit(&json!({"event": "device_revoked", "device_id": device_id, "log_index": r.log_index}));
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    const R: &str = "r_01ARZ3NDEKTSV4RRFFQ69G5FAV";
    const ALICE: &str = "ps_aaaaaaaaaaaaaaaa";
    const MALLORY: &str = "ps_mmmmmmmmmmmmmmmm";
    const ME: &str = "ps_zzzzzzzzzzzzzzzz";
    const OK: &str = "ok_00000000000000000000000000000000";

    fn grant(kind: &str, subject: &str, label: &str, body_subject: &str) -> SignResponse {
        SignResponse {
            kind: kind.into(),
            repo_id: R.into(),
            repo_slug: "acme/widget".into(),
            subject: subject.into(),
            subject_username: label.into(),
            body_to_sign: grant_body(R, body_subject, OK, 1),
            ..SignResponse::default()
        }
    }

    fn approve(who: &str) -> Ask<'_> {
        Ask { kind: Kind::DonorApproved, repo_slug: "acme/widget", subject: Some(who), device: false }
    }

    /// A217/A218 reproducers: a compromised background process (fake node.sock) proposes
    /// entries the human did not ask for; none of them binds.
    #[test]
    fn owner_signs_only_what_was_asked() {
        // The honest case: handle or pseudonym.
        assert!(bind(&approve("alice"), Some(ME), &grant("DONOR_APPROVED", ALICE, "alice", ALICE)).is_ok());
        assert!(bind(&approve(ALICE), Some(ME), &grant("DONOR_APPROVED", ALICE, "alice", ALICE)).is_ok());
        // Another kind than the command (members add proposed for `approve`).
        assert!(bind(&approve("alice"), Some(ME), &grant("MEMBER_ADDED", ALICE, "alice", ALICE)).is_err());
        // Another subject than the argument.
        assert!(bind(&approve("alice"), Some(ME), &grant("DONOR_APPROVED", MALLORY, "mallory", MALLORY)).is_err());
        // Shows alice, the body signs mallory.
        assert!(bind(&approve("alice"), Some(ME), &grant("DONOR_APPROVED", ALICE, "alice", MALLORY)).is_err());
        // Another project.
        let mut p = grant("DONOR_APPROVED", ALICE, "alice", ALICE);
        p.repo_slug = "evil/repo".into();
        assert!(bind(&approve("alice"), Some(ME), &p).is_err());
        // A pseudonym argument never matches a label.
        assert!(bind(&approve(MALLORY), Some(ME), &grant("DONOR_APPROVED", ALICE, MALLORY, ALICE)).is_err());
        // `members add d_… --device` (E32): the label is the device id, the body its owner's pseudonym.
        let dev = "d_01J0000000000000000000000D";
        let member = |device| Ask { kind: Kind::MemberAdded, repo_slug: "acme/widget", subject: Some(dev), device };
        assert!(bind(&member(true), Some(ME), &grant("MEMBER_ADDED", ALICE, dev, ALICE)).is_ok());
        assert!(bind(&member(false), Some(ME), &grant("MEMBER_ADDED", ALICE, dev, ALICE)).is_err(), "only with --device");
        assert!(bind(&member(true), Some(ME), &grant("MEMBER_ADDED", ALICE, "d_01J0000000000000000000000E", ALICE)).is_err(), "another device");
        // A hidden DONOR_APPROVED offered as the "claim" of an approve (A217) never binds as a claim.
        let claim_ask = Ask { kind: Kind::RepoClaimed, repo_slug: "acme/widget", subject: None, device: false };
        assert!(bind(&claim_ask, Some(ME), &grant("DONOR_APPROVED", MALLORY, "mallory", MALLORY)).is_err());
    }

    #[test]
    fn claims_name_this_account() {
        let claim = |owner: &str| SignResponse {
            kind: "REPO_CLAIMED".into(),
            repo_id: R.into(),
            repo_slug: "acme/widget".into(),
            subject: owner.into(),
            body_to_sign: claim_body(R, "github", "123", owner, OK, 1),
            ..SignResponse::default()
        };
        let ask = Ask { kind: Kind::RepoClaimed, repo_slug: "acme/widget", subject: None, device: false };
        let b = bind(&ask, Some(ME), &claim(ME)).unwrap();
        assert_eq!(b.claim, Some(("github".into(), "123".into())));
        assert!(bind(&ask, Some(ME), &claim(MALLORY)).is_err(), "claim for another account");
        assert!(bind(&ask, None, &claim(ME)).is_err(), "unknown account");
    }
}
