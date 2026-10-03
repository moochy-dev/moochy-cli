//! Organisation owner entries (CONTRACT §19, spec/KEYLOG.md §2c): `moochy claim --org`, `moochy org
//! add|remove`, `moochy accept <donor> --org` sign ORG_CLAIMED, ORG_REPO_ADDED/REMOVED and
//! DONOR_APPROVED/REVOKED on the org's `o_` id with the owner key, under the same rules as
//! `owner::sign` (A217/A218): the app on `node.sock` only proposes; the CLI binds the decoded body to
//! the command, checks every id and handle with the server's `Lookup` (dialed directly; an org is
//! looked up as `org:<path>`, a namespace no project slug can reach), shows what it signs, and
//! rebuilds the body with its own signer and time. `moochy org list` reads the owner's covered
//! projects from the requests pushed over the link (else the public orgs API).

use crate::config::Home;
use crate::owner::{check_own_key, key_path, load, register, rt, status, submit};
use crate::pb::link::{LookupRequest, LookupResponse};
use crate::pb::local::{ApproveRequest, ClaimRequest, OrgRepoRequest, SignResponse, SubmitEntryRequest};
use crate::util::{Result, auth, clean, internal, now_ms, usage};
use moochy_keylog::Kind;
use moochy_keylog::entry::{Body, grant_body, is_id, org_claim_body, org_repo_body, owner_key_id, parse_body, sig_message};
use moochy_proto::crypto::SignKey;
use serde_json::json;

/// What the command asked for.
#[derive(Clone, Copy, Debug)]
pub enum Op<'a> {
    Claim,
    /// A project in the link's canonical form.
    Repo { repo: &'a str, remove: bool },
    /// A handle or a pseudonym (`ps_…`).
    Donor { donor: &'a str, revoke: bool },
}

impl Op<'_> {
    fn kind(self) -> Kind {
        match self {
            Op::Claim => Kind::OrgClaimed,
            Op::Repo { remove: false, .. } => Kind::OrgRepoAdded,
            Op::Repo { remove: true, .. } => Kind::OrgRepoRemoved,
            Op::Donor { revoke: false, .. } => Kind::DonorApproved,
            Op::Donor { revoke: true, .. } => Kind::DonorRevoked,
        }
    }
}

/// The exact fields one signature covers, after binding.
#[derive(Clone, Debug, PartialEq, Eq)]
struct Bound {
    kind: Kind,
    org_id: String,
    /// ORG_REPO_*: the project's `r_` id.
    repo_id: String,
    /// Claims: this account. Approvals: the donor's pseudonym.
    subject: String,
    /// Claims: provider and the provider's numeric org id.
    claim: Option<(String, String)>,
    /// Approvals: the donor as the server confirmed it (empty until then: never signed).
    name: String,
    /// The org and the project as typed, then as the server names them.
    org: String,
    repo: String,
}

/// Check one previewed entry against the command and this account; `Err` = never sign it. Ids are
/// checked by prefix here, from the body: a Lookup that lies cannot turn a project into an org.
fn bind(op: Op<'_>, org: &str, me: Option<&str>, p: &SignResponse) -> Result<Bound> {
    let refuse = |what: &str| usage(format!("refusing to sign: the app proposed {what}, not what you asked for"));
    let kind = Kind::from_name(&p.kind).ok_or_else(|| refuse("an unknown entry kind"))?;
    if kind != op.kind() {
        return Err(refuse(&format!("{} instead of {}", kind.name(), op.kind().name())));
    }
    if !p.org_path.eq_ignore_ascii_case(org) {
        return Err(refuse(&format!("organisation {}", clean(&p.org_path))));
    }
    let provider = org.split('/').next().unwrap_or_default();
    let b = Bound { kind, org_id: String::new(), repo_id: String::new(), subject: String::new(), claim: None, name: String::new(), org: org.into(), repo: String::new() };
    match (parse_body(kind, &p.body_to_sign), op) {
        (Ok(Body::OrgClaim { org_id, provider: pv, provider_org_id, owner, .. }), Op::Claim) => {
            if !is_id(org_id, "o_") || org_id != p.org_id || me != Some(owner) || pv != provider || provider_org_id.is_empty() || !provider_org_id.bytes().all(|c| c.is_ascii_digit()) {
                return Err(refuse("an organisation claim naming another account or organisation"));
            }
            Ok(Bound { org_id: org_id.into(), subject: owner.into(), claim: Some((pv.into(), provider_org_id.into())), name: owner.into(), ..b })
        }
        (Ok(Body::OrgRepo { org_id, repo_id, .. }), Op::Repo { repo, .. }) => {
            let same_repo = crate::config::canonical_slug(&p.repo_slug).is_some_and(|s| s.eq_ignore_ascii_case(repo));
            if !is_id(org_id, "o_") || !is_id(repo_id, "r_") || org_id != p.org_id || repo_id != p.repo_id || !same_repo {
                return Err(refuse("an entry for another organisation or project"));
            }
            Ok(Bound { org_id: org_id.into(), repo_id: repo_id.into(), repo: repo.into(), ..b })
        }
        (Ok(Body::Grant { repo_id: org_id, subject, .. }), Op::Donor { donor, .. }) => {
            // A project id here would accept the donor for that project behind the org's label.
            if !is_id(org_id, "o_") || org_id != p.org_id || org_id != p.repo_id || subject != p.subject || !subject.starts_with("ps_") {
                return Err(refuse("an approval for another organisation or account"));
            }
            // A pseudonym is matched exactly; a handle only by the server's Lookup.
            let name = if donor.starts_with("ps_") {
                if donor != subject {
                    return Err(refuse(&format!("donor {}", clean(subject))));
                }
                donor
            } else if donor.starts_with("d_") {
                return Err(usage("an organisation accepts accounts (a handle or ps_…), not devices"));
            } else {
                ""
            };
            Ok(Bound { org_id: org_id.into(), subject: subject.into(), name: name.into(), ..b })
        }
        _ => Err(refuse("a malformed entry")),
    }
}

/// A218: what the server (dialed directly, never through `node.sock`) says `slug` is; `org:<path>`
/// for an organisation. With `who`, the handle lookup is signed by the owner key.
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
            Err(s) if s.code() == tonic::Code::Unimplemented => Err(usage("refusing to sign: this Moochy server cannot confirm names (no Lookup); update the relay")),
            Err(s) if s.code() == tonic::Code::NotFound => Err(usage(match who {
                Some((h, ..)) => format!("refusing to sign: the server does not know {} as a donor of {} (or it is not yours); use their pseudonym (ps_…) shown on the web", clean(h), clean(slug)),
                None => format!("refusing to sign: the server knows no claimed {} (organisations: once this server supports them)", clean(slug)),
            })),
            Err(s) => Err(status(&s)),
        }
    };
    rt.block_on(async { tokio::time::timeout(std::time::Duration::from_secs(20), call).await.map_err(|_| crate::util::net("the Moochy server did not answer the lookup"))? })
}

/// A218: the bound entry must name what the server answered; the confirmation then shows the
/// server's names.
fn check_org(b: &mut Bound, handle: Option<&str>, l: &LookupResponse) -> Result<()> {
    let refuse = |what: String| usage(format!("refusing to sign: the app and the server disagree on {what}"));
    let path = l.repo_slug.strip_prefix("org:").unwrap_or_default();
    if l.repo_id != b.org_id || !path.eq_ignore_ascii_case(&b.org) {
        return Err(refuse(format!("the organisation ({} vs {} {})", clean(&b.org_id), clean(&l.repo_slug), clean(&l.repo_id))));
    }
    if let Some(h) = handle {
        if !l.handle.eq_ignore_ascii_case(h) || l.pseudonym != b.subject {
            return Err(refuse(format!("who {} is ({} vs {})", clean(h), clean(&b.subject), clean(&l.pseudonym))));
        }
        b.name.clone_from(&l.handle);
    }
    path.clone_into(&mut b.org);
    Ok(())
}

fn check_repo(b: &mut Bound, l: &LookupResponse) -> Result<()> {
    if l.repo_id != b.repo_id {
        return Err(usage(format!("refusing to sign: the app and the server disagree on the project ({} vs {})", clean(&b.repo_id), clean(&l.repo_id))));
    }
    b.repo.clone_from(&l.repo_slug);
    Ok(())
}

/// Every signed field, in words (A217); `--yes` skips only the question.
fn confirm(b: &Bound, signer: &str, yes: bool) -> Result<()> {
    let org = format!("the organisation {} ({})", clean(&b.org), clean(&b.org_id));
    let line = match b.kind {
        Kind::OrgClaimed => format!("your account ({}) is the owner of {org}", clean(&b.subject)),
        Kind::OrgRepoAdded => format!("donations to {org} may fund your project {} ({})", clean(&b.repo), clean(&b.repo_id)),
        Kind::OrgRepoRemoved => format!("donations to {org} no longer fund your project {} ({})", clean(&b.repo), clean(&b.repo_id)),
        Kind::DonorApproved | Kind::DonorRevoked if b.name.is_empty() => return Err(usage("refusing to sign: the server did not confirm who this is")),
        Kind::DonorApproved => format!("{} may donate tokens to (and see the requests of) every project of {org}", who(b)),
        Kind::DonorRevoked => format!("{} may no longer donate to {org}", who(b)),
        _ => return Err(internal("unexpected entry kind")),
    };
    eprintln!("Owner signature {}:", b.kind.name());
    eprintln!("  {line}");
    if let Some((prov, id)) = &b.claim {
        eprintln!("  organisation at {} (id {})", clean(prov), clean(id));
    }
    eprintln!("  signed by your owner key {signer}");
    if !yes && !matches!(crate::owner::ask("Type yes to sign: ", false)?.as_str(), "yes" | "y") {
        return Err(usage("not signed"));
    }
    Ok(())
}

fn who(b: &Bound) -> String {
    if b.name == b.subject { format!("the account {}", clean(&b.subject)) } else { format!("{} ({}, as the Moochy server says)", clean(&b.name), clean(&b.subject)) }
}

/// The body from the BOUND fields only, with this key and the current time (KEYLOG §5).
fn body(b: &Bound, signer: &str, now: u64) -> Vec<u8> {
    match (&b.claim, b.kind) {
        (Some((provider, provider_org_id)), _) => org_claim_body(&b.org_id, provider, provider_org_id, &b.subject, signer, now),
        (None, Kind::OrgRepoAdded | Kind::OrgRepoRemoved) => org_repo_body(&b.org_id, &b.repo_id, signer, now),
        (None, _) => grant_body(&b.org_id, &b.subject, signer, now),
    }
}

/// `moochy claim --org`, `moochy org add|remove`, `moochy accept|approve <donor> --org`.
pub fn sign(home: &Home, org: &str, op: Op<'_>, yes: bool) -> Result<()> {
    let cfg = home.load()?;
    let rt = rt()?;
    let preview = rt.block_on(async {
        let mut c = crate::ctl::connect(&home.socket_path()).await?;
        let org = org.to_owned();
        let r = match op {
            Op::Claim => c.claim(ClaimRequest { org, dry_run: true, ..ClaimRequest::default() }).await,
            Op::Repo { repo, remove } => c.org_repo(OrgRepoRequest { org, repo: repo.into(), remove, dry_run: true }).await,
            Op::Donor { donor, revoke } => c.approve(ApproveRequest { org, donor: donor.into(), revoke, dry_run: true, ..ApproveRequest::default() }).await,
        };
        r.map(tonic::Response::into_inner).map_err(|s| if s.code() == tonic::Code::Unimplemented { usage(clean(s.message()).into_owned()) } else { status(&s) })
    })?;
    let me = cfg.pseudonym.as_deref();
    let mut b = bind(op, org, me, &preview)?;
    let has_key = key_path(home, cfg.relay.as_deref()).exists();
    if !has_key {
        eprintln!("No owner key yet: one will be created (a separate key with its own passphrase) and registered in the public key log.");
        if !yes && !matches!(crate::owner::ask("Type yes to create it: ", false)?.as_str(), "yes" | "y") {
            return Err(usage("nothing signed"));
        }
    }
    let key = if has_key { load(home, cfg.relay.as_deref())? } else { register(home, &rt, None)? };
    check_own_key(home, &cfg, me, &key)?;
    let org_slug = format!("org:{org}");
    match op {
        // Like a project claim: the org is not claimed yet, the body names this account.
        Op::Claim => {}
        Op::Repo { repo, .. } => {
            check_org(&mut b, None, &lookup(&cfg, &rt, &org_slug, None)?)?;
            check_repo(&mut b, &lookup(&cfg, &rt, repo, None)?)?;
            eprintln!("Checked with the Moochy server (not through the app): {} is {}; {} is {}", clean(&b.org), clean(&b.org_id), clean(&b.repo), clean(&b.repo_id));
        }
        Op::Donor { donor, .. } => {
            let handle = (!donor.starts_with("ps_")).then_some(donor);
            let who = match (handle, me) {
                (Some(h), Some(me)) => Some((h, me, &key)),
                (Some(_), None) => return Err(auth("not logged in: run `moochy login` first")),
                _ => None,
            };
            check_org(&mut b, handle, &lookup(&cfg, &rt, &org_slug, who)?)?;
            let person = handle.map(|h| format!("; {} is {}", clean(h), clean(&b.subject))).unwrap_or_default();
            eprintln!("Checked with the Moochy server (not through the app): {} is {}{person}", clean(&b.org), clean(&b.org_id));
        }
    }
    let signer = owner_key_id(&key.public());
    confirm(&b, &signer, yes)?;
    let body = body(&b, &signer, now_ms());
    let sig = key.sign(&sig_message(b.kind, &body));
    drop(key);
    let done = rt.block_on(submit(home, SubmitEntryRequest { request_id: preview.request_id.clone(), kind: b.kind.name().into(), body, sigs: vec![sig.to_vec()] }))?;
    crate::util::emit(&json!({"request_id": done.request_id, "kind": b.kind.name(), "org": b.org, "org_id": b.org_id, "repo": b.repo, "repo_id": b.repo_id,
        "subject": b.subject, "subject_username": b.name, "signer": done.signer, "issued_at_ms": done.issued_at_ms, "signed": done.signed, "log_index": done.log_index}));
    Ok(())
}

#[derive(serde::Deserialize)]
struct OrgInfo {
    org_id: String,
    path: String,
    #[serde(default)]
    repos: Vec<Covered>,
}

#[derive(serde::Deserialize, serde::Serialize)]
struct Covered {
    repo_id: String,
    slug: String,
}

/// `moochy org list --org ORG`: the projects the org's donations fund. The owner's view comes over
/// the link (WIRING §4: the dedicated link port is gRPC only): exactly the ORG_REPO_REMOVED requests
/// the relay pushes, each checked against the verified key log. Anyone else, or a node without a
/// key log, reads the server's public orgs API (`GET /api/v1/orgs/{provider}/{path…}`, §19.6).
pub fn list(home: &Home, org: &str, json_out: bool) -> Result<()> {
    let cfg = home.load()?;
    let info = match owned(home, &cfg, org) {
        Ok(Some(i)) => i,
        // The server does not know the org: the public API would not either.
        Err(e) if e.exit == crate::util::Exit::Usage => return Err(e),
        _ => public(&cfg, org)?,
    };
    if json_out {
        crate::util::emit(&json!({"org": info.path, "org_id": info.org_id, "repos": info.repos}));
    } else if info.repos.is_empty() {
        println!("{} ({}) funds none of your projects yet: moochy org add <PROJECT> --org {}", clean(&info.path), clean(&info.org_id), clean(&info.path));
    } else {
        println!("Donations to {} ({}) fund:", clean(&info.path), clean(&info.org_id));
        for r in &info.repos {
            println!("  {} ({})", clean(&r.slug), clean(&r.repo_id));
        }
    }
    Ok(())
}

/// The owner's view (WIRING §4). `Ok(None)`: not this account's org in the key log.
fn owned(home: &Home, cfg: &crate::config::Config, org: &str) -> Result<Option<OrgInfo>> {
    let Some(me) = cfg.pseudonym.as_deref() else { return Ok(None) };
    let rt = rt()?;
    let pushed = rt.block_on(async {
        let mut c = crate::ctl::connect(&home.socket_path()).await?;
        c.pending(crate::pb::local::PendingRequest {}).await.map(tonic::Response::into_inner).map_err(|s| status(&s))
    })?;
    // The org id from the server (dialed directly), never from the app's list.
    let l = lookup(cfg, &rt, &format!("org:{org}"), None).map_err(|e| if e.exit == crate::util::Exit::Usage { usage(format!("the server knows no claimed organisation {}", clean(org))) } else { e })?;
    let path = l.repo_slug.strip_prefix("org:").unwrap_or_default();
    if !is_id(&l.repo_id, "o_") || !path.eq_ignore_ascii_case(org) {
        return Err(internal("the server answered for another organisation"));
    }
    let rows: Vec<&SignResponse> = pushed.requests.iter().filter(|q| q.kind == Kind::OrgRepoRemoved.name() && q.org_id == l.repo_id && is_id(&q.repo_id, "r_")).collect();
    let ids: Vec<&str> = std::iter::once(l.repo_id.as_str()).chain(rows.iter().map(|q| q.repo_id.as_str())).collect();
    let Some(owners) = crate::keylog::KeyLog::owners(home, cfg, &ids) else { return Ok(None) };
    let mut owners = owners.into_iter();
    if owners.next().flatten().as_deref() != Some(me) {
        return Ok(None);
    }
    // ponytail: checks both claims name this account; that ORG_REPO_ADDED is still active needs a
    // coverage query in moochy-keylog (requested), until then the relay's push is trusted for it.
    let mut repos = Vec::new();
    for (q, owner) in rows.into_iter().zip(owners) {
        if owner.as_deref() == Some(me) {
            repos.push(Covered { repo_id: q.repo_id.clone(), slug: q.repo_slug.clone() });
        } else {
            eprintln!("warning: the server lists {} ({}) as funded by {}, but your key log does not show it as your project: not listed", clean(&q.repo_slug), clean(&q.repo_id), clean(path));
        }
    }
    Ok(Some(OrgInfo { org_id: l.repo_id.clone(), path: path.to_owned(), repos }))
}

/// Anyone's view: the server's public orgs API, on an origin that serves HTTP.
fn public(cfg: &crate::config::Config, org: &str) -> Result<OrgInfo> {
    let relay = crate::tls::Origin::parse(cfg.relay.as_deref().unwrap_or(crate::config::DEFAULT_RELAY))?;
    let f = moochy_keylog::fetch::Fetcher::with_roots(&format!("{}/api/v1/orgs/", relay.url()), std::time::Duration::from_secs(20), crate::tls::roots(cfg.ca_file.as_deref())?)
        .map_err(|e| internal(format!("orgs API: {e}")))?;
    let raw = f.get(org, 256 * 1024).map_err(|e| {
        let e = e.to_string();
        if e.contains(" 404") {
            usage(format!("the server knows no claimed organisation {} (or it does not support organisations yet)", clean(org)))
        } else {
            crate::util::net(format!("could not read organisation {} from the server: {}", clean(org), clean(&e)))
        }
    })?;
    let info: OrgInfo = serde_json::from_slice(&raw).map_err(|_| internal("the server's organisation answer is not the expected JSON"))?;
    if !is_id(&info.org_id, "o_") || !info.path.eq_ignore_ascii_case(org) || info.repos.iter().any(|r| !is_id(&r.repo_id, "r_")) {
        return Err(internal("the server answered for another organisation"));
    }
    Ok(info)
}

#[cfg(test)]
mod tests {
    use super::*;

    const ORG: &str = "o_01ARZ3NDEKTSV4RRFFQ69G5FAV";
    const OTHER: &str = "o_01ARZ3NDEKTSV4RRFFQ69G5FAW";
    const R: &str = "r_01ARZ3NDEKTSV4RRFFQ69G5FAV";
    const ME: &str = "ps_zzzzzzzzzzzzzzzz";
    const ALICE: &str = "ps_aaaaaaaaaaaaaaaa";
    const OK: &str = "ok_00000000000000000000000000000000";

    fn resp(kind: &str, repo_id: &str, subject: &str, body: Vec<u8>) -> SignResponse {
        SignResponse { kind: kind.into(), repo_id: repo_id.into(), subject: subject.into(), body_to_sign: body, org_id: ORG.into(), org_path: "github/acme".into(), ..SignResponse::default() }
    }

    #[test]
    fn claim_names_this_account_and_the_typed_provider() {
        let ok = resp("ORG_CLAIMED", "", ME, org_claim_body(ORG, "github", "900", ME, OK, 1));
        let b = bind(Op::Claim, "github/acme", Some(ME), &ok).unwrap();
        assert_eq!(b.claim, Some(("github".into(), "900".into())));
        // Rebuilt with our signer and time, the body still says the same thing.
        assert!(matches!(parse_body(Kind::OrgClaimed, &body(&b, OK, 2)), Ok(Body::OrgClaim { org_id: ORG, owner: ME, provider_org_id: "900", .. })));
        assert!(bind(Op::Claim, "github/acme", Some(ME), &resp("ORG_CLAIMED", "", ALICE, org_claim_body(ORG, "github", "900", ALICE, OK, 1))).is_err(), "another owner");
        assert!(bind(Op::Claim, "github/acme", Some(ME), &resp("ORG_CLAIMED", "", ME, org_claim_body(ORG, "gitlab", "900", ME, OK, 1))).is_err(), "gitlab group behind github/");
        assert!(bind(Op::Claim, "github/acme", Some(ME), &resp("ORG_CLAIMED", "", ME, org_claim_body(R, "github", "900", ME, OK, 1))).is_err(), "a project id");
        assert!(bind(Op::Claim, "github/evil", Some(ME), &ok).is_err(), "label of another org");
        assert!(bind(Op::Claim, "github/acme", None, &ok).is_err(), "unknown account");
        let mut wrong = ok.clone();
        wrong.org_id = OTHER.into();
        assert!(bind(Op::Claim, "github/acme", Some(ME), &wrong).is_err(), "label id differs from body");
    }

    #[test]
    fn repo_entries_bind_both_ids() {
        let mut p = resp("ORG_REPO_ADDED", R, "", org_repo_body(ORG, R, OK, 1));
        p.repo_slug = "acme/app1".into();
        let add = Op::Repo { repo: "acme/app1", remove: false };
        let mut b = bind(add, "github/acme", Some(ME), &p).unwrap();
        assert!(bind(Op::Repo { repo: "acme/app1", remove: true }, "github/acme", Some(ME), &p).is_err(), "kind");
        assert!(bind(Op::Repo { repo: "acme/side", remove: false }, "github/acme", Some(ME), &p).is_err(), "another project");
        let swapped = resp("ORG_REPO_ADDED", R, "", org_repo_body(R, ORG, OK, 1));
        assert!(bind(add, "github/acme", Some(ME), &swapped).is_err(), "ids swapped");
        // The server must agree on both.
        let org = LookupResponse { repo_slug: "org:github/acme".into(), repo_id: ORG.into(), ..LookupResponse::default() };
        check_org(&mut b, None, &org).unwrap();
        assert!(check_org(&mut b.clone(), None, &LookupResponse { repo_id: OTHER.into(), ..org.clone() }).is_err());
        assert!(check_org(&mut b.clone(), None, &LookupResponse { repo_slug: "github/acme".into(), ..org }).is_err(), "a project answer");
        assert!(check_repo(&mut b.clone(), &LookupResponse { repo_id: "r_01ARZ3NDEKTSV4RRFFQ69G5FAW".into(), ..LookupResponse::default() }).is_err());
        assert!(matches!(parse_body(Kind::OrgRepoAdded, &body(&b, OK, 2)), Ok(Body::OrgRepo { org_id: ORG, repo_id: R, .. })));
    }

    #[test]
    fn org_approval_is_an_org_id_and_a_confirmed_donor() {
        let p = resp("DONOR_APPROVED", ORG, ALICE, grant_body(ORG, ALICE, OK, 1));
        let approve = |d| Op::Donor { donor: d, revoke: false };
        // A project approval behind the org's label.
        let mut proj = resp("DONOR_APPROVED", R, ALICE, grant_body(R, ALICE, OK, 1));
        proj.org_id = R.into();
        assert!(bind(approve("alice"), "github/acme", Some(ME), &proj).is_err());
        assert!(bind(approve(ME), "github/acme", Some(ME), &p).is_err(), "pseudonym mismatch");
        assert!(bind(approve("d_x"), "github/acme", Some(ME), &p).is_err(), "devices");
        let b = bind(approve(ALICE), "github/acme", Some(ME), &p).unwrap();
        assert_eq!(b.name, ALICE);
        // A handle: unconfirmed (never signed) until the server's Lookup says who it is.
        let mut b = bind(approve("alice"), "github/acme", Some(ME), &p).unwrap();
        assert!(confirm(&b, OK, true).is_err());
        let l = LookupResponse { repo_slug: "org:github/acme".into(), repo_id: ORG.into(), handle: "alice".into(), pseudonym: ALICE.into() };
        assert!(check_org(&mut b.clone(), Some("alice"), &LookupResponse { pseudonym: ME.into(), ..l.clone() }).is_err(), "the server names another account");
        check_org(&mut b, Some("alice"), &l).unwrap();
        assert_eq!(b.name, "alice");
        assert!(matches!(parse_body(Kind::DonorApproved, &body(&b, OK, 2)), Ok(Body::Grant { repo_id: ORG, subject: ALICE, .. })));
    }
}
