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

/// Public halves of this user's owner keys, written by `moochy owner init|rotate`
/// (`<state>/owner_keys`: one base64url key per line).
pub fn public_keys(home: &Home) -> Vec<[u8; 32]> {
    std::fs::read_to_string(home.state_dir().join("owner_keys")).map(|s| s.lines().filter_map(|l| crate::util::b64d32(l.trim())).take(16).collect()).unwrap_or_default()
}

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
    if let Ok(p) = std::env::var("MOOCHY_OWNER_PASSPHRASE") {
        let p = Zeroizing::new(p);
        if !p.is_empty() {
            return Ok(p);
        }
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

/// `moochy owner init` (first key) / `moochy owner rotate` (new key, the current one signs too).
pub fn init(home: &Home, rotate: bool) -> Result<()> {
    let cfg = home.load()?;
    let relay = cfg.relay.as_deref();
    let pseudonym = cfg.pseudonym.clone().ok_or_else(|| auth("not logged in: run `moochy login` first"))?;
    let path = key_path(home, relay);
    let prev = if rotate {
        Some(load(home, relay)?)
    } else {
        if path.exists() {
            return Err(usage("this device already has an owner key (`moochy owner rotate` replaces it)"));
        }
        None
    };
    let new = SignKey::from_seed(&Zeroizing::new(crate::util::rand_bytes::<32>()?));
    let pass = passphrase(true)?;
    let body = owner_key_body(&pseudonym, &new.public(), prev.as_ref().map(SignKey::public).as_ref(), now_ms());
    let msg = sig_message(Kind::OwnerKeyAdded, &body);
    let mut sigs = vec![new.sign(&msg).to_vec()];
    sigs.extend(prev.as_ref().map(|p| p.sign(&msg).to_vec()));
    // Keep the key only once the log accepted it.
    let r = rt()?.block_on(submit(home, SubmitEntryRequest { request_id: String::new(), kind: "OWNER_KEY_ADDED".into(), body, sigs }))?;
    store(home, relay, &new, &pass)?;
    crate::util::emit(&json!({"event": if rotate { "owner_key_rotated" } else { "owner_key_added" }, "owner_key": owner_key_id(&new.public()), "log_index": r.log_index}));
    Ok(())
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
    let kind = Kind::from_name(&preview.kind).ok_or_else(|| internal("unknown entry kind"))?;
    let meaning = match kind {
        Kind::DonorApproved => "may donate tokens to (and see the requests of)",
        Kind::DonorRevoked => "may no longer donate to",
        Kind::MemberAdded => "may use the donated tokens of",
        Kind::MemberRemoved => "may no longer use the donated tokens of",
        _ => "is the owner of",
    };
    eprintln!(
        "You are about to sign {} with your owner key:\n  {} ({}) {meaning} {} ({})",
        preview.kind,
        clean(&preview.subject_username),
        clean(&preview.subject),
        clean(&preview.repo_slug),
        clean(&preview.repo_id)
    );
    if !yes && !matches!(ask("Type yes to sign: ", false)?.as_str(), "yes" | "y") {
        return Err(usage("not signed"));
    }
    if yes && std::env::var_os("MOOCHY_OWNER_PASSPHRASE").is_none() && tty().is_err() {
        return Err(usage("--yes without a terminal needs MOOCHY_OWNER_PASSPHRASE (CI only)"));
    }
    let key = load(home, cfg.relay.as_deref())?;
    let signer = owner_key_id(&key.public());
    let now = now_ms();
    let body = if kind == Kind::RepoClaimed {
        let Ok(Body::Claim { repo_id, provider, provider_repo_id, owner, .. }) = parse_body(kind, &preview.body_to_sign) else {
            return Err(internal("claim request is malformed"));
        };
        if cfg.pseudonym.as_deref() != Some(owner) || repo_id != preview.repo_id {
            return Err(usage("this claim names another account or repository"));
        }
        claim_body(repo_id, provider, provider_repo_id, owner, &signer, now)
    } else {
        grant_body(&preview.repo_id, &preview.subject, &signer, now)
    };
    let sig = key.sign(&sig_message(kind, &body));
    drop(key);
    let done = rt.block_on(submit(home, SubmitEntryRequest { request_id: preview.request_id.clone(), kind: preview.kind.clone(), body, sigs: vec![sig.to_vec()] }))?;
    crate::util::emit(&json!({"request_id": done.request_id, "kind": done.kind, "repo": done.repo_slug, "repo_id": done.repo_id, "subject": done.subject,
        "subject_username": done.subject_username, "signer": done.signer, "issued_at_ms": done.issued_at_ms, "signed": done.signed, "log_index": done.log_index}));
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
    let body = moochy_keylog::entry::lp(&[id.as_bytes(), pseudonym.as_bytes(), &sign_pub, &enc_pub, suite.as_bytes(), roles.as_bytes(), b""]);
    let pop = new.sign_key().sign(&moochy_keylog::entry::pop_message(&sign_pub, &enc_pub, suite));
    let endorse = old.sign(&moochy_keylog::entry::lp(&[b"moochy/v1/key-rotate", &body]));
    let r = rt()?.block_on(submit(home, SubmitEntryRequest { request_id: format!("rotate-{id}"), kind: "KEY_ADDED".into(), body, sigs: vec![pop.to_vec(), endorse.to_vec()] }))?;
    sec.device = Some(new);
    keystore::save(home, &cfg, &sec)?;
    cfg.device_id = Some(id.clone());
    home.save(&cfg)?;
    crate::util::emit(&json!({"event": "key_rotated", "device_id": id, "log_index": r.log_index, "note": "restart the app (`moochy down && moochy up`) within 24 h to use the new key"}));
    Ok(())
}
