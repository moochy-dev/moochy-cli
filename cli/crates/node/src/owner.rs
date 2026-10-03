//! Owner key (CONTRACT §15.4, spec/KEYLOG.md §4): a separate Ed25519 key, encrypted at rest,
//! decrypted only by the foreground CLI for one approval / membership / claim (and the signed
//! `Lookup` that checks its names with the server, A218), and dropped right after. The background Node never reads the secret;
//! it knows only the public halves (`<state>/owner_keys`, for the monitor's owner alerts) and
//! relays the signed entry (`SubmitEntry`).
//!
//! Passphrase: `MOOCHY_OWNER_PASSPHRASE` (headless, CI) or typed on the terminal (never stdin, so
//! a tool piping into `moochy` cannot answer). It is deliberately not the keystore passphrase:
//! the background process runs with that one.

use crate::config::Home;
use crate::pb::link::{LookupRequest, LookupResponse};
use crate::pb::local::{ApproveRequest, ClaimRequest, MembersRequest, SignResponse, SubmitEntryRequest, members_request::Op};
use crate::util::{Ctx as _, Result, auth, b64e, clean, internal, now_ms, usage};
use moochy_keylog::Kind;
use moochy_keylog::state::OwnerKeyProof;
use moochy_keylog::entry::{Body, authorized_owner_key_body, claim_body, grant_body, owner_key_body, owner_key_id, parse_body, sig_message};
use moochy_proto::crypto::SignKey;
use serde_json::json;
use std::io::{BufRead as _, Write as _};
use zeroize::Zeroizing;

const AAD: &[u8] = b"moochy/owner-key/v1";

pub(crate) fn key_path(home: &Home, relay: Option<&str>) -> std::path::PathBuf {
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

pub(crate) fn ask(prompt: &str, hidden: bool) -> Result<Zeroizing<String>> {
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
pub(crate) fn load(home: &Home, relay: Option<&str>) -> Result<SignKey> {
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

pub(crate) fn rt() -> Result<tokio::runtime::Runtime> {
    tokio::runtime::Builder::new_current_thread().enable_all().build().ctx("runtime")
}

pub(crate) fn status(s: &tonic::Status) -> crate::util::Error {
    match s.code() {
        tonic::Code::NotFound | tonic::Code::FailedPrecondition | tonic::Code::InvalidArgument => usage(clean(s.message()).into_owned()),
        tonic::Code::Unavailable | tonic::Code::DeadlineExceeded => crate::util::net(clean(s.message()).into_owned()),
        _ => internal(clean(s.message()).into_owned()),
    }
}

pub(crate) async fn submit(home: &Home, req: SubmitEntryRequest) -> Result<SignResponse> {
    let mut c = crate::ctl::connect(&home.socket_path()).await?;
    c.submit_entry(req).await.map(tonic::Response::into_inner).map_err(|s| status(&s))
}

/// Create an owner key, register it in the key log (OWNER_KEY_ADDED, signed by the new key and,
/// on rotation, by `prev`), and keep it encrypted only once the log accepted it.
pub(crate) fn register(home: &Home, rt: &tokio::runtime::Runtime, prev: Option<&SignKey>) -> Result<SignKey> {
    let cfg = home.load()?;
    let pseudonym = cfg.pseudonym.clone().ok_or_else(|| auth("not logged in: run `moochy login` first"))?;
    let new = SignKey::from_seed(&Zeroizing::new(crate::util::rand_bytes::<32>()?));
    let pass = passphrase(true)?;
    let body = owner_key_body(&pseudonym, &new.public(), prev.map(SignKey::public).as_ref(), now_ms());
    let msg = sig_message(Kind::OwnerKeyAdded, &body);
    let mut sigs = vec![new.sign(&msg).to_vec()];
    sigs.extend(prev.map(|p| p.sign(&msg).to_vec()));
    let id = owner_key_id(&new.public());
    if prev.is_none() {
        // A224 (KEYLOG §4c): the relay holds a first key until the human proves it on the web.
        eprintln!("Registering owner key {id}. If the server asks for proof, it emails your confirmed address a link naming {id}: open it signed in and confirm (it expires in 10 min). Waiting…");
    }
    let r = match rt.block_on(submit(home, SubmitEntryRequest { request_id: String::new(), kind: "OWNER_KEY_ADDED".into(), body, sigs })).map_err(proof_refusal) {
        // The account has a passkey (KEYLOG §4b): a first CLI key needs it to co-sign on the web.
        Err(e) if prev.is_none() && e.msg.contains("owner_key_exists") => {
            let authorizer = match crate::keylog::KeyLog::passkey_authorizer(home, &cfg, &pseudonym) {
                Some(Some(a)) => a,
                Some(None) => {
                    return Err(match crate::keylog::KeyLog::active_owner_key(home, &cfg, &pseudonym) {
                        // A224: a CLI owner key this device did not create (init checked there is none here).
                        Some(Some(id)) => auth(format!("the public key log already lists an owner key {id} for your account that was not created on this device. If you made it on another machine, sign there; if not, the app here or your account is compromised: revoke {id} on moochy.dev")),
                        _ => usage("this account already has an owner key: if it is a passkey you added on the web, trust it here first (`moochy owner trust ok_…`, from the key-log alert) and run this again"),
                    });
                }
                None => return Err(usage("this account already has an owner key (the public key log, needed to check its passkeys, is not configured here)")),
            };
            let body = authorized_owner_key_body(&pseudonym, &new.public(), now_ms(), &authorizer);
            let sig = new.sign(&sig_message(Kind::OwnerKeyAdded, &body));
            eprintln!("Your account has a passkey ({authorizer}): approve owner key {id} with it on moochy.dev (within 10 min). Waiting…");
            rt.block_on(submit(home, SubmitEntryRequest { request_id: String::new(), kind: "OWNER_KEY_ADDED".into(), body, sigs: vec![sig.to_vec()] })).map_err(proof_refusal)?
        }
        r => r?,
    };
    // Only now (the log answered with its index) is the key kept and reported.
    store(home, cfg.relay.as_deref(), &new, &pass)?;
    // How the log bound it, from this machine's verified copy (it may lag the answer a little).
    let mut row = None;
    for _ in 0..20 {
        row = crate::keylog::KeyLog::owner_key_row(home, &cfg, &pseudonym, &id);
        if !matches!(row, Some(None)) {
            break;
        }
        std::thread::sleep(std::time::Duration::from_millis(500));
    }
    let proof = match row {
        Some(Some(k)) => Some(proof_name(k.proof)),
        _ => None,
    };
    match row {
        Some(Some(k)) => eprintln!("Owner key {id} is in the public key log at #{}: {}.", k.idx, proof_text(k.proof)),
        _ => eprintln!("Owner key {id} is in the public key log at #{} (`moochy owner status` shows how it was bound once this machine's copy of the log has it).", r.log_index),
    }
    // A224: unless this machine's log shows the proof, the residual is said plainly.
    let proven = matches!(row, Some(Some(k)) if k.proof != OwnerKeyProof::None);
    if prev.is_none() && !proven {
        eprintln!("Unless the server bound it with your confirmed email, it took this key on this device's word alone (trust on first use).");
        eprintln!("Check on moochy.dev that your account lists exactly this owner key; your other devices alert on any owner key they did not see created.");
    }
    crate::util::emit(&json!({"event": if prev.is_some() { "owner_key_rotated" } else { "owner_key_added" }, "owner_key": id, "log_index": r.log_index, "first": prev.is_none(), "proof": proof}));
    Ok(new)
}

/// KEYLOG §4c: how an owner key was bound, in words.
fn proof_text(p: OwnerKeyProof) -> &'static str {
    match p {
        OwnerKeyProof::Email => "bound with your confirmed email",
        OwnerKeyProof::Authorizer => "authorized by another owner key of yours (your passkey)",
        OwnerKeyProof::Rotation => "a rotation signed by your previous owner key",
        OwnerKeyProof::None => "bound before the email-proof rule, on the server's word alone (trust on first use); rotating keeps it trusted only if it was yours",
    }
}

fn proof_name(p: OwnerKeyProof) -> &'static str {
    match p {
        OwnerKeyProof::None => "none",
        OwnerKeyProof::Email => "email",
        OwnerKeyProof::Authorizer => "authorizer",
        OwnerKeyProof::Rotation => "rotation",
    }
}

/// KEYLOG §4c/§10: the relay's refusals of an owner key, as plain sentences.
fn proof_refusal(e: crate::util::Error) -> crate::util::Error {
    let say = |m: &str| usage(format!("{m}; nothing was registered"));
    if e.msg.contains("owner_key_proof") {
        say("the server refused an owner key without proof: this server does not offer the email confirmation yet (add a passkey on moochy.dev first, then run `moochy owner init` again so the passkey approves it)")
    } else if e.msg.contains("email_changed_recently") {
        say("your email address changed less than 72 hours ago: for your safety the server binds a first owner key by email only after that (or approve it with a passkey you already have)")
    } else if e.msg.contains(": refused") {
        say("you (or someone signed in to your account) refused this owner key on moochy.dev; if that was not you, secure your account")
    } else if e.msg.contains("skew") {
        say("the confirmation came too late (more than 10 minutes): run `moochy owner init` again and confirm the new email")
    } else if e.msg.contains("did not acknowledge") {
        say("nobody confirmed within 10 minutes")
    } else {
        e
    }
}

/// What any owner key of the account can sign (KEYLOG §2, CONTRACT §19): `owner status` and
/// `owner trust` say it, organisations included.
const SIGNS: &str = "signs for your projects and your organisations: claims, the donors you accept, members, and which of your projects an organisation's donations fund";

/// `moochy owner status` (KEYLOG §4c): this account's CLI owner key as the public key log shows it.
pub fn show_status(home: &Home) -> Result<()> {
    let cfg = home.load()?;
    let me = cfg.pseudonym.clone().ok_or_else(|| auth("not logged in: run `moochy login` first"))?;
    let here = key_path(home, cfg.relay.as_deref()).exists();
    let Some(active) = crate::keylog::KeyLog::active_owner_key(home, &cfg, &me) else {
        return Err(usage("no public key log on this machine (log_key): owner keys cannot be checked"));
    };
    let orgs = crate::keylog::KeyLog::owned_orgs(home, &cfg, &me).unwrap_or_default();
    for l in org_lines(&orgs) {
        eprintln!("{l}");
    }
    let orgs_json: Vec<_> = orgs.iter().map(|(o, r)| json!({"org_id": o, "repos": r})).collect();
    // §19.2a: as the relay last pushed them to the running app (none when it is not running).
    let claims = rt()?
        .block_on(async {
            let mut c = crate::ctl::connect(&home.socket_path()).await.ok()?;
            c.pending(crate::pb::local::PendingRequest {}).await.ok()
        })
        .map(|r| r.into_inner().claims)
        .unwrap_or_default();
    for l in claim_lines(&claims) {
        eprintln!("{l}");
    }
    let claims_json: Vec<_> = claims
        .iter()
        .map(|c| json!({"target_id": c.target_id, "path": c.path, "verified_at_ms": c.verified_at_ms, "paused_since_ms": c.paused_since_ms, "releases_at_ms": c.releases_at_ms}))
        .collect();
    let Some(id) = active else {
        eprintln!("No CLI owner key in the public key log for your account{}.", if here { " (this device has a key file the log does not list: run `moochy owner init` after removing it, or check the log)" } else { "" });
        crate::util::emit(&json!({"event": "owner_status", "owner_key": null, "key_here": here, "orgs": orgs_json, "claims": claims_json}));
        return Ok(());
    };
    let row = crate::keylog::KeyLog::owner_key_row(home, &cfg, &me, &id).flatten();
    match row {
        Some(k) => eprintln!("Owner key {id} (log #{}): {}.{}", k.idx, proof_text(k.proof), if here { "" } else { " Its secret is not on this device." }),
        None => eprintln!("Owner key {id}."),
    }
    eprintln!("It {SIGNS}.");
    crate::util::emit(&json!({"event": "owner_status", "owner_key": id, "log_index": row.map(|k| k.idx), "proof": row.map(|k| proof_name(k.proof)), "key_here": here, "orgs": orgs_json, "claims": claims_json}));
    Ok(())
}

/// `owner status` (§19.2a): claims not re-verified at the provider for a while. Paused: no new
/// request reaches their donations until the next web sign-in; released if still not re-verified.
fn claim_lines(claims: &[crate::pb::local::ClaimState]) -> Vec<String> {
    let day = |ms: i64| crate::worker::utc_day(u64::try_from(ms).unwrap_or(0));
    claims
        .iter()
        .map(|c| {
            let what = format!("{} ({})", clean(&c.path), clean(&c.target_id));
            let release = if c.releases_at_ms > 0 { format!(", or it is released on {}", day(c.releases_at_ms)) } else { String::new() };
            if c.paused_since_ms > 0 {
                format!("Claim {what} PAUSED since {}: no new request reaches its donations. Sign in on the web to re-verify it{release}.", day(c.paused_since_ms))
            } else {
                format!("Claim {what} last verified {}: sign in on the web to re-verify it before it pauses{release}.", day(c.verified_at_ms))
            }
        })
        .collect()
}

/// `owner status` (§19): the organisations this account owns in the verified key log, each with
/// the projects its donations fund. Ids are validated ASCII in the log; still printed `clean`.
fn org_lines(orgs: &[(String, Vec<String>)]) -> Vec<String> {
    orgs.iter()
        .map(|(o, r)| {
            let covers = if r.is_empty() { "funds none of your projects yet (`moochy org add`)".to_owned() } else { format!("funds {}", r.iter().map(|x| clean(x)).collect::<Vec<_>>().join(", ")) };
            format!("Organisation {}: {covers}.", clean(o))
        })
        .collect()
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
    /// `--device`: the device's owner according to the verified key log (read by the CLI from
    /// disk, never from `node.sock`); the signed pseudonym must be it.
    device_owner: Option<&'a str>,
}

/// The exact fields one signature will cover, after binding.
#[derive(Clone, Debug, PartialEq, Eq)]
struct Bound {
    kind: Kind,
    repo_id: String,
    /// Grants: the subject pseudonym / device id. Claims: the owner (this account).
    subject: String,
    /// Claims only: provider and provider repo id from the claim request.
    claim: Option<(String, String)>,
    /// Who the confirmation names, from a source the app cannot forge (A218): the pseudonym or
    /// device id typed, or the handle as the server's `Lookup` resolved it. Empty: a handle not
    /// yet confirmed by the server, which is never signed.
    name: String,
    /// The project as typed, then as the server's `Lookup` names it.
    slug: String,
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
    let b = match (parse_body(kind, &p.body_to_sign), ask.subject) {
        (Ok(Body::Claim { repo_id, provider, provider_repo_id, owner, .. }), None) => {
            if repo_id != p.repo_id || me != Some(owner) || p.subject != owner {
                return Err(refuse("a claim naming another account or project"));
            }
            Bound { kind, repo_id: repo_id.into(), subject: owner.into(), claim: Some((provider.into(), provider_repo_id.into())), name: owner.into(), slug: ask.repo_slug.into() }
        }
        (Ok(Body::Grant { repo_id, subject, .. }), Some(arg)) => {
            if repo_id != p.repo_id || subject != p.subject {
                return Err(refuse("a body that differs from what it shows"));
            }
            // Pseudonyms and device ids are matched exactly. A handle is bound by the server's
            // `Lookup` (`check_lookup`), never by the app's label: unconfirmed until then.
            let (ok, name) = if arg.starts_with("ps_") {
                (arg == subject, arg)
            } else if arg.starts_with("d_") {
                (ask.device && arg == p.subject_username && ask.device_owner.is_none_or(|o| o == subject) && subject.starts_with("ps_"), arg)
            } else {
                (true, "")
            };
            if !ok {
                return Err(refuse(&format!("subject {}", clean(subject))));
            }
            Bound { kind, repo_id: repo_id.into(), subject: subject.into(), claim: None, name: name.into(), slug: ask.repo_slug.into() }
        }
        _ => return Err(refuse("a malformed entry")),
    };
    // §19: these commands name a project. The same body on an organisation id (`o_…`) would
    // accept the donor for every project the organisation covers, behind a project's label.
    if !b.repo_id.starts_with("r_") {
        return Err(refuse(&format!("an entry for {}, not a project", clean(&b.repo_id))));
    }
    Ok(b)
}

/// A218: what the server itself (dialed directly, not through `node.sock`) says the project and
/// the handle are. Fails closed: no answer (including a server without Lookup) means no signature.
fn lookup(cfg: &crate::config::Config, rt: &tokio::runtime::Runtime, slug: &str, who: Option<(&str, &str, &SignKey)>) -> Result<LookupResponse> {
    let relay = cfg.relay.as_deref().unwrap_or(crate::config::DEFAULT_RELAY);
    let mut q = LookupRequest { repo_slug: slug.into(), ..LookupRequest::default() };
    if let Some((handle, me, key)) = who {
        let now = now_ms();
        q.handle = handle.into();
        q.owner = me.into();
        q.owner_key_id = owner_key_id(&key.public());
        q.issued_at_ms = i64::try_from(now).map_err(|_| internal("clock"))?;
        q.sig = key.sign(&moochy_keylog::entry::lookup_request_message(handle, slug, me, now)).to_vec().into();
    }
    let call = async {
        let (ch, _) = crate::link::dial(cfg.ca_file.as_deref(), &crate::tls::Origin::parse(relay)?).await?;
        match crate::link::client(ch).lookup(q).await {
            Ok(r) => Ok(r.into_inner()),
            Err(s) if s.code() == tonic::Code::Unimplemented => {
                Err(usage("refusing to sign: this Moochy server cannot confirm names (no Lookup); update the relay".to_owned()))
            }
            Err(s) if s.code() == tonic::Code::NotFound => Err(usage(match who {
                Some((h, ..)) => format!("refusing to sign: the server does not know {} as a donor or member of {} (or the project is not yours); use their pseudonym (ps_…) shown on the web", clean(h), clean(slug)),
                None => format!("refusing to sign: the server knows no claimed project {}", clean(slug)),
            })),
            Err(s) => Err(status(&s)),
        }
    };
    rt.block_on(async { tokio::time::timeout(std::time::Duration::from_secs(20), call).await.map_err(|_| crate::util::net("the Moochy server did not answer the lookup"))? })
}

/// A218: the bound entry must name what the server answered; the confirmation then shows the
/// server's names (handle, project), never the app's labels.
fn check_lookup(b: &mut Bound, handle: Option<&str>, l: &LookupResponse) -> Result<()> {
    let refuse = |what: String| usage(format!("refusing to sign: the app and the server disagree on {what}"));
    if l.repo_id != b.repo_id {
        return Err(refuse(format!("the project ({} vs {})", clean(&b.repo_id), clean(&l.repo_id))));
    }
    if let Some(h) = handle
        && (!l.handle.eq_ignore_ascii_case(h) || l.pseudonym != b.subject)
    {
        return Err(refuse(format!("who {} is ({} vs {})", clean(h), clean(&b.subject), clean(&l.pseudonym))));
    }
    if handle.is_some() {
        b.name.clone_from(&l.handle);
    }
    b.slug.clone_from(&l.repo_slug);
    Ok(())
}

/// Show every signed field of one entry and ask (A217): `--yes` skips only the question.
fn confirm(b: &Bound, signer: &str, extra: &str, yes: bool) -> Result<()> {
    if b.name.is_empty() || b.slug.is_empty() {
        return Err(usage("refusing to sign: the server did not confirm who or which project this is"));
    }
    let meaning = match b.kind {
        Kind::DonorApproved => "may donate tokens to (and see the requests of)",
        Kind::DonorRevoked => "may no longer donate to",
        Kind::MemberAdded => "may use the donated tokens of",
        Kind::MemberRemoved => "may no longer use the donated tokens of",
        _ => "is the owner of",
    };
    eprintln!("Owner signature {}:", b.kind.name());
    let who = if b.claim.is_some() {
        format!("your account ({})", clean(&b.subject))
    } else if b.name.starts_with("d_") {
        // A device as a member: the signature covers the device's whole account.
        format!("the account {} (all its devices, including {})", clean(&b.subject), clean(&b.name))
    } else if b.name == b.subject {
        format!("the account {}", clean(&b.subject))
    } else {
        format!("{} ({}, as the Moochy server says)", clean(&b.name), clean(&b.subject))
    };
    eprintln!("  {who} {meaning} {} ({})", clean(&b.slug), clean(&b.repo_id));
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

/// What was signed, named as the CLI bound it (not the app's labels).
fn emit_signed(done: &SignResponse, b: &Bound) {
    crate::util::emit(&json!({"request_id": done.request_id, "kind": b.kind.name(), "repo": b.slug, "repo_id": b.repo_id, "subject": b.subject,
        "subject_username": b.name, "signer": done.signer, "issued_at_ms": done.issued_at_ms, "signed": done.signed, "log_index": done.log_index}));
}

/// A224: sign only with the account's active owner key as the public key log shows it. A first
/// owner key is trust-on-first-use (the log takes it on the session's word): if the app on this
/// machine registered a key of its own instead of ours, the log names that one, and this refuses.
pub(crate) fn check_own_key(home: &Home, cfg: &crate::config::Config, me: Option<&str>, key: &SignKey) -> Result<()> {
    let mine = owner_key_id(&key.public());
    match me.map(|me| crate::keylog::KeyLog::active_owner_key(home, cfg, me)) {
        Some(Some(Some(id))) if id != mine => Err(auth(format!(
            "refusing to sign: the public key log says your account's owner key is {id}, not this device's {mine}. If you just rotated it, wait a minute for the log and retry; otherwise the app on this machine or your account is compromised: do not approve anything, revoke {id} on moochy.dev and run `moochy owner rotate`"
        ))),
        Some(None) | None => {
            eprintln!("WARNING: no public key log on this machine: your owner key {mine} is not checked against it");
            Ok(())
        }
        Some(Some(_)) => Ok(()),
    }
}

/// `moochy approve|members|claim`: preview what the relay asks, show it, get an explicit yes and
/// the owner passphrase, rebuild the body with the owner key id and the current time
/// (KEYLOG §5), sign, and hand the entry to the Node to relay.
#[allow(clippy::too_many_arguments, clippy::fn_params_excessive_bools)]
pub fn sign(home: &Home, slug: &str, words: &[&str], yes: bool, revoke: bool, device: bool, cap: i64) -> Result<()> {
    let (also, donor) = match (revoke, words) {
        (true, ["approve", donor]) => (covering_orgs(home, slug, donor, yes)?, *donor),
        _ => (Vec::new(), ""),
    };
    let done = sign_entries(home, slug, words, yes, revoke, device, cap);
    // The org revokes the human asked for run even if the project's own entry failed.
    for org in &also {
        crate::org::sign(home, org, crate::org::Op::Donor { donor, revoke: true }, false)?;
    }
    done
}

/// A269 (§19.4): a project-level DONOR_REVOKED does not stop a donor approved through an
/// organisation of yours that funds the project. Such organisations come from the verified key
/// log; the org revoke is offered and needs its own yes (`--yes` only prints the command: it never
/// signs more than was typed). Returns the organisations to revoke the donor for.
fn covering_orgs(home: &Home, slug: &str, donor: &str, yes: bool) -> Result<Vec<String>> {
    let cfg = home.load()?;
    let Some(orgs) = cfg.pseudonym.as_deref().and_then(|me| crate::keylog::KeyLog::owned_orgs(home, &cfg, me)) else { return Ok(Vec::new()) };
    if orgs.iter().all(|(_, r)| r.is_empty()) {
        return Ok(Vec::new());
    }
    let rt = rt()?;
    // The project's id from the server, dialed directly; the revoke reports its own errors.
    let Ok(l) = lookup(&cfg, &rt, slug, None) else { return Ok(Vec::new()) };
    let ids: Vec<String> = orgs.into_iter().filter(|(_, r)| r.contains(&l.repo_id)).map(|(o, _)| o).collect();
    if ids.is_empty() {
        return Ok(Vec::new());
    }
    // The org's path: from the relay's pushed ORG_REPO_REMOVED offer for this (org, project).
    let pushed = rt
        .block_on(async {
            let mut c = crate::ctl::connect(&home.socket_path()).await.ok()?;
            c.pending(crate::pb::local::PendingRequest {}).await.ok()
        })
        .map(|r| r.into_inner().requests)
        .unwrap_or_default();
    let mut out = Vec::new();
    for o in &ids {
        let path = pushed.iter().find(|q| q.org_id == *o && q.repo_id == l.repo_id).and_then(|q| crate::config::canonical_org(&q.org_path));
        let target = path.as_deref().map_or_else(|| format!("<path of {}>", clean(o)), |p| clean(p).into_owned());
        eprintln!(
            "Note: your organisation {target} ({}) funds {}. If it accepted {}, they keep serving {} through it after this revoke; to stop them on every project of the organisation: moochy approve {} --revoke --org {target}",
            clean(o),
            clean(&l.repo_slug),
            clean(donor),
            clean(&l.repo_slug),
            clean(donor)
        );
        if let Some(p) = path
            && !yes
            && matches!(ask(&format!("Revoke {} for {} too? Type yes: ", clean(donor), clean(&p)), false)?.as_str(), "yes" | "y")
        {
            out.push(p);
        }
    }
    Ok(out)
}

fn sign_entries(home: &Home, slug: &str, words: &[&str], yes: bool, revoke: bool, device: bool, cap: i64) -> Result<()> {
    let cfg = home.load()?;
    let rt = rt()?;
    // `--device` (a CI device as a member): only to add, and the device's account comes from the
    // verified key log on disk, never from the app's labels (a compromised app could put any
    // pseudonym behind the device id the owner typed). The signature covers the whole account.
    let device_owner = match (device, words) {
        (true, ["members", "add", d]) => match crate::keylog::KeyLog::device_owner(home, &cfg, d) {
            Some(Some(ps)) => Some(ps),
            Some(None) => return Err(usage(format!("{} is not a device in the public key log", clean(d)))),
            None if std::env::var("MOOCHY_INSECURE_DEV").as_deref() == Ok("1") => {
                eprintln!("WARNING: no key log on this machine: the device's account is not checked (MOOCHY_INSECURE_DEV)");
                None
            }
            None => return Err(usage("--device needs the public key log (log_key) to check the device's account")),
        },
        (true, _) => return Err(usage("--device is only for `members add` (to remove, use the member's account)")),
        _ => None,
    };
    let preview = rt.block_on(async {
        let mut c = crate::ctl::connect(&home.socket_path()).await?;
        let r = match words {
            ["approve", donor] => c.approve(ApproveRequest { repo: slug.into(), donor: (*donor).into(), dry_run: true, revoke, ..ApproveRequest::default() }).await,
            ["members", op, user] => {
                let op = if *op == "add" { Op::Add } else { Op::Remove };
                c.members(MembersRequest { repo: slug.into(), op: op as i32, user: (*user).into(), cap_uusd_month: cap, device, dry_run: true }).await
            }
            _ => c.claim(ClaimRequest { repo: slug.into(), dry_run: true, ..ClaimRequest::default() }).await,
        };
        r.map(tonic::Response::into_inner).map_err(|s| status(&s))
    })?;
    let want = match words {
        ["approve", donor] => Ask { kind: if revoke { Kind::DonorRevoked } else { Kind::DonorApproved }, repo_slug: slug, subject: Some(donor), device: false, device_owner: None },
        ["members", op, user] => Ask { kind: if *op == "add" { Kind::MemberAdded } else { Kind::MemberRemoved }, repo_slug: slug, subject: Some(user), device, device_owner: device_owner.as_deref() },
        _ => Ask { kind: Kind::RepoClaimed, repo_slug: slug, subject: None, device: false, device_owner: None },
    };
    let me = cfg.pseudonym.as_deref();
    let mut main = bind(&want, me, &preview)?;
    // An approval needs an owner-signed claim of the same project naming this account
    // (KEYLOG §5): offered as its own entry, shown in full, confirmed on its own.
    let mut claim = (want.kind != Kind::RepoClaimed)
        .then(|| rt.block_on(async {
            let mut c = crate::ctl::connect(&home.socket_path()).await.ok()?;
            c.claim(ClaimRequest { repo: slug.into(), dry_run: true, ..ClaimRequest::default() }).await.ok().map(tonic::Response::into_inner)
        }))
        .flatten()
        .and_then(|p| bind(&Ask { kind: Kind::RepoClaimed, repo_slug: slug, subject: None, device: false, device_owner: None }, me, &p).ok().filter(|b| b.repo_id == main.repo_id).map(|b| (b, p)));
    let has_key = key_path(home, cfg.relay.as_deref()).exists();
    if !has_key {
        eprintln!("No owner key yet: one will be created (a separate key with its own passphrase) and registered in the public key log.");
        if !yes && !matches!(ask("Type yes to create it: ", false)?.as_str(), "yes" | "y") {
            return Err(usage("nothing signed"));
        }
    }
    let signer = if has_key { "(existing)".to_owned() } else { "(new)".to_owned() };
    // The key signs the handle lookup (A218) before anything is shown; entries only after yes.
    let key = if has_key { load(home, cfg.relay.as_deref())? } else { register(home, &rt, None)? };
    check_own_key(home, &cfg, me, &key)?;
    if want.kind != Kind::RepoClaimed {
        let handle = want.subject.filter(|s| !s.starts_with("ps_") && !s.starts_with("d_"));
        let who = match (handle, me) {
            (Some(h), Some(me)) => Some((h, me, &key)),
            (Some(_), None) => return Err(auth("not logged in: run `moochy login` first")),
            _ => None,
        };
        let l = lookup(&cfg, &rt, slug, who)?;
        check_lookup(&mut main, handle, &l)?;
        if let Some((b, _)) = claim.as_mut() {
            b.slug.clone_from(&l.repo_slug);
        }
        let person = handle.map(|h| format!("; {} is {}", clean(h), clean(&l.pseudonym))).unwrap_or_default();
        eprintln!("Checked with the Moochy server (not through the app): {} is {}{person}", clean(&l.repo_slug), clean(&l.repo_id));
    }
    if let Some((b, _)) = &claim {
        confirm(b, &signer, "", yes)?;
    }
    let extra = if want.kind == Kind::MemberAdded && cap > 0 { format!("; monthly limit {} (a project setting, not signed)", crate::util::fmt_dollars(u64::try_from(cap).unwrap_or(0))) } else { String::new() };
    confirm(&main, &signer, &extra, yes)?;
    if let Some((b, p)) = &claim {
        emit_signed(&sign_one(home, &rt, &key, b, p)?, b);
    }
    let done = sign_one(home, &rt, &key, &main, &preview)?;
    drop(key);
    emit_signed(&done, &main);
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

/// `moochy owner trust <ok_id>` (CONTRACT §16.6): an owner key of this account created elsewhere
/// (a passkey registered on the web) is shown, confirmed by the human, and marked known in the
/// running app's key-log monitor (persisted), so it stops raising `unknown_*` alerts.
pub fn trust(home: &Home, id: &str, yes: bool) -> Result<()> {
    if !id.starts_with("ok_") || id.len() > 64 || !id.bytes().all(|c| c.is_ascii_alphanumeric() || c == b'_') {
        return Err(usage("owner trust <ok_…> (the id in the key-log alert)"));
    }
    let rt = rt()?;
    let call = |dry_run: bool| {
        rt.block_on(async {
            let mut c = crate::ctl::connect(&home.socket_path()).await?;
            c.trust_owner_key(crate::pb::local::TrustOwnerKeyRequest { owner_key_id: id.into(), dry_run }).await.map(tonic::Response::into_inner).map_err(|s| status(&s))
        })
    };
    let d = call(true)?;
    // A224: how the key got in, from this machine's verified copy of the log (not the app's word).
    let cfg = home.load()?;
    let how = match cfg.pseudonym.as_deref().and_then(|me| crate::keylog::KeyLog::owner_key_row(home, &cfg, me, id)) {
        Some(Some(k)) if k.idx != d.log_index => return Err(auth(format!("refusing: the app says {id} is at #{}, the key log at #{}", d.log_index, k.idx))),
        Some(Some(k)) if k.email_proof == Some(true) => "a passkey registered with only an emailed link (trust on first use: whoever read that email could have made it)",
        Some(Some(k)) if k.email_proof.is_some() => "a passkey approved by another owner key of yours",
        Some(Some(k)) => proof_text(k.proof),
        Some(None) => return Err(usage(format!("{id} is not an owner key of your account in the public key log"))),
        None => "not checked: no public key log on this machine",
    };
    eprintln!("Owner key {id} of your account, registered in the public key log at #{}{}: {how}.", d.log_index, if d.revoked { " (since revoked)" } else { "" });
    eprintln!("Trust it only if YOU registered it (e.g. a passkey you added on moochy.dev): it {SIGNS}. If not, your account may be compromised.");
    if !yes && !matches!(ask("Type yes to trust it: ", false)?.as_str(), "yes" | "y") {
        return Err(usage("not trusted"));
    }
    let r = call(false)?;
    crate::util::emit(&json!({"event": "owner_key_trusted", "owner_key": id, "log_index": r.log_index, "revoked": r.revoked}));
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn paused_claims_say_how_to_resume_and_when_they_go() {
        let c = |paused| crate::pb::local::ClaimState { target_id: "o_x".into(), path: "github/acme".into(), verified_at_ms: 1_700_000_000_000, paused_since_ms: paused, releases_at_ms: 1_707_776_000_000 };
        let l = claim_lines(&[c(1_702_592_000_000), c(0)]);
        assert_eq!(l[0], "Claim github/acme (o_x) PAUSED since 2023-12-14: no new request reaches its donations. Sign in on the web to re-verify it, or it is released on 2024-02-12.");
        assert!(l[1].starts_with("Claim github/acme (o_x) last verified 2023-11-14: sign in on the web"));
    }

    const R: &str = "r_01ARZ3NDEKTSV4RRFFQ69G5FAV";
    const ALICE: &str = "ps_aaaaaaaaaaaaaaaa";
    const MALLORY: &str = "ps_mmmmmmmmmmmmmmmm";
    const ME: &str = "ps_zzzzzzzzzzzzzzzz";
    const OK: &str = "ok_00000000000000000000000000000000";

    #[test]
    fn org_lines_name_orgs_and_their_projects() {
        let orgs = vec![("o_a".to_owned(), vec!["r_1".to_owned(), "r_2".to_owned()]), ("o_b\x1b[2J".to_owned(), vec![])];
        let l = org_lines(&orgs);
        assert_eq!(l[0], "Organisation o_a: funds r_1, r_2.");
        assert!(l[1].starts_with("Organisation o_b") && !l[1].contains('\x1b') && l[1].contains("funds none"), "{}", l[1]);
    }

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

    /// The server's `Lookup` answer for `handle` on the project.
    fn server(handle: &str, ps: &str) -> LookupResponse {
        LookupResponse { repo_slug: "acme/widget".into(), repo_id: R.into(), handle: handle.into(), pseudonym: ps.into() }
    }

    /// What `sign` does before showing anything: bind to the command, then to the server's answer.
    fn verified(ask: &Ask<'_>, p: &SignResponse, l: &LookupResponse) -> Result<Bound> {
        let mut b = bind(ask, Some(ME), p)?;
        check_lookup(&mut b, ask.subject.filter(|s| !s.starts_with("ps_") && !s.starts_with("d_")), l)?;
        Ok(b)
    }

    fn approve(who: &str) -> Ask<'_> {
        Ask { kind: Kind::DonorApproved, repo_slug: "acme/widget", subject: Some(who), device: false, device_owner: None }
    }

    /// A217/A218 reproducers: a compromised background process (fake node.sock) proposes
    /// entries the human did not ask for; none of them binds.
    #[test]
    fn owner_signs_only_what_was_asked() {
        // The honest case: handle or pseudonym.
        let b = verified(&approve("alice"), &grant("DONOR_APPROVED", ALICE, "alice", ALICE), &server("alice", ALICE)).unwrap();
        assert_eq!((b.name.as_str(), b.subject.as_str(), b.slug.as_str()), ("alice", ALICE, "acme/widget"));
        let b = verified(&approve(ALICE), &grant("DONOR_APPROVED", ALICE, "alice", ALICE), &server("", "")).unwrap();
        assert_eq!(b.name, ALICE, "a pseudonym argument is shown as typed, never with the app's label");
        // A218 residual: a handle is never bound by the app's label. Unconfirmed until the
        // server answers, and an unconfirmed entry is never shown or signed.
        let unconfirmed = bind(&approve("alice"), Some(ME), &grant("DONOR_APPROVED", MALLORY, "alice", MALLORY)).unwrap();
        assert!(unconfirmed.name.is_empty() && confirm(&unconfirmed, "", "", true).is_err());
        // The app labels mallory as "alice": the server says alice is ALICE.
        assert!(verified(&approve("alice"), &grant("DONOR_APPROVED", MALLORY, "alice", MALLORY), &server("alice", ALICE)).is_err());
        // The server's canonical handle is what is shown, whatever the label says.
        let b = verified(&approve("Alice"), &grant("DONOR_APPROVED", ALICE, "someone-else", ALICE), &server("alice", ALICE)).unwrap();
        assert_eq!(b.name, "alice");
        // Another kind than the command (members add proposed for `approve`).
        assert!(bind(&approve("alice"), Some(ME), &grant("MEMBER_ADDED", ALICE, "alice", ALICE)).is_err());
        // Another subject than the argument.
        assert!(verified(&approve("alice"), &grant("DONOR_APPROVED", MALLORY, "mallory", MALLORY), &server("alice", ALICE)).is_err());
        // Shows alice, the body signs mallory.
        assert!(verified(&approve("alice"), &grant("DONOR_APPROVED", ALICE, "alice", MALLORY), &server("alice", ALICE)).is_err());
        // Another project.
        let mut p = grant("DONOR_APPROVED", ALICE, "alice", ALICE);
        p.repo_slug = "evil/repo".into();
        assert!(bind(&approve("alice"), Some(ME), &p).is_err());
        // §19: an org approval (the donor for every covered project) behind the project's label,
        // with a Lookup that agrees (a lying server).
        let org = "o_01ARZ3NDEKTSV4RRFFQ69G5FAV";
        let mut p = grant("DONOR_APPROVED", ALICE, "alice", ALICE);
        (p.repo_id, p.body_to_sign) = (org.into(), grant_body(org, ALICE, OK, 1));
        let mut s = server("alice", ALICE);
        s.repo_id = org.into();
        assert!(bind(&approve("alice"), Some(ME), &p).is_err());
        assert!(verified(&approve("alice"), &p, &s).is_err());
        // A pseudonym argument never matches a label.
        assert!(bind(&approve(MALLORY), Some(ME), &grant("DONOR_APPROVED", ALICE, MALLORY, ALICE)).is_err());
        // `members add d_… --device` (E32): the label is the device id, the body its owner's pseudonym.
        let dev = "d_01J0000000000000000000000D";
        let member = |device| Ask { kind: Kind::MemberAdded, repo_slug: "acme/widget", subject: Some(dev), device, device_owner: Some(ALICE) };
        assert!(bind(&member(true), Some(ME), &grant("MEMBER_ADDED", ALICE, dev, ALICE)).is_ok());
        assert!(bind(&member(false), Some(ME), &grant("MEMBER_ADDED", ALICE, dev, ALICE)).is_err(), "only with --device");
        assert!(bind(&member(true), Some(ME), &grant("MEMBER_ADDED", ALICE, "d_01J0000000000000000000000E", ALICE)).is_err(), "another device");
        // The device id the owner typed, but another account in the signed body: the key log
        // says the device is alice's (review of 311f70964).
        assert!(bind(&member(true), Some(ME), &grant("MEMBER_ADDED", MALLORY, dev, MALLORY)).is_err(), "device behind another account");
        // A hidden DONOR_APPROVED offered as the "claim" of an approve (A217) never binds as a claim.
        let claim_ask = Ask { kind: Kind::RepoClaimed, repo_slug: "acme/widget", subject: None, device: false, device_owner: None };
        assert!(bind(&claim_ask, Some(ME), &grant("DONOR_APPROVED", MALLORY, "mallory", MALLORY)).is_err());
    }

    /// A218: a compromised app labels mallory as "alice"; the server's own answer catches it.
    #[test]
    fn lookup_must_agree() {
        let b = Bound { kind: Kind::DonorApproved, repo_id: R.into(), subject: MALLORY.into(), claim: None, name: String::new(), slug: "acme/widget".into() };
        let check_lookup = |b: &Bound, h: Option<&str>, l: &LookupResponse| check_lookup(&mut b.clone(), h, l);
        let l = |repo: &str, ps: &str| LookupResponse { repo_slug: "acme/widget".into(), repo_id: repo.into(), handle: "alice".into(), pseudonym: ps.into() };
        assert!(check_lookup(&b, Some("alice"), &l(R, MALLORY)).is_ok());
        assert!(check_lookup(&b, Some("Alice"), &l(R, MALLORY)).is_ok(), "handles are case-insensitive");
        assert!(check_lookup(&b, Some("alice"), &l(R, ALICE)).is_err(), "server says alice is someone else");
        assert!(check_lookup(&b, Some("bob"), &l(R, MALLORY)).is_err(), "answer for another handle");
        assert!(check_lookup(&b, None, &l("r_01ARZ3NDEKTSV4RRFFQ69G5FAW", "")).is_err(), "another project");
        assert!(check_lookup(&b, None, &l(R, "")).is_ok(), "pseudonym argument: repo only");
    }

    /// KEYLOG §4c: the relay's owner-key codes reach the user as sentences, never as success.
    #[test]
    fn owner_key_refusals_are_sentences() {
        let r = |code: &str| proof_refusal(usage(format!("relay refused the entry: {code}"))).msg;
        assert!(r("owner_key_proof").contains("without proof") && r("owner_key_proof").contains("nothing was registered"));
        assert!(r("email_changed_recently").contains("72 hours"));
        assert!(r("skew").contains("too late"));
        assert!(r("refused").contains("refused this owner key"));
        assert!(proof_refusal(crate::util::net("relay did not acknowledge the entry")).msg.contains("within 10 minutes"));
        assert_eq!(r("bad_sig"), "relay refused the entry: bad_sig");
        assert_eq!(proof_name(OwnerKeyProof::Email), "email");
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
        let ask = Ask { kind: Kind::RepoClaimed, repo_slug: "acme/widget", subject: None, device: false, device_owner: None };
        let b = bind(&ask, Some(ME), &claim(ME)).unwrap();
        assert_eq!(b.claim, Some(("github".into(), "123".into())));
        assert!(bind(&ask, Some(ME), &claim(MALLORY)).is_err(), "claim for another account");
        assert!(bind(&ask, None, &claim(ME)).is_err(), "unknown account");
    }
}
