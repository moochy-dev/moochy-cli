//! Organisation owner entries (CONTRACT §19, spec/KEYLOG.md §2c): `moochy claim --org`, `moochy org
//! add|remove`, `moochy accept <donor> --org` sign ORG_CLAIMED, ORG_REPO_ADDED/REMOVED and
//! DONOR_APPROVED/REVOKED on the org's `o_` id with the owner key, under the same rules as
//! `owner::sign` (A217/A218): the app on `node.sock` only proposes; the CLI binds the decoded body to
//! the command, checks every id and handle with the server's `Lookup` (dialed directly; an org is
//! looked up as `org:<path>`, a namespace no project slug can reach), shows what it signs, and
//! rebuilds the body with its own signer and time. `moochy org list` reads the owner's covered
//! projects from the requests pushed over the link (else the public orgs API).
//!
//! A person profile (CONTRACT §24: `moochy claim --person`, `moochy person add|remove|list`,
//! `moochy accept <donor> --person`) is the same machinery on an `m_` id: PERSON_CLAIMED,
//! PERSON_REPO_ADDED/REMOVED and DONOR_* on the person, looked up as `person:<path>`.

use crate::config::Home;
use crate::owner::{check_own_key, key_path, load, register, rt, status, submit};
use crate::pb::link::{LookupRequest, LookupResponse};
use crate::pb::local::{ApproveRequest, ClaimRequest, OrgRepoRequest, SignResponse, SubmitEntryRequest};
use crate::util::{Result, auth, clean, internal, now_ms, usage};
use moochy_keylog::Kind;
use moochy_keylog::entry::{Body, grant_body, is_id, org_claim_body, org_repo_body, owner_key_id, parse_body, person_claim_body, person_repo_body, sig_message};
use moochy_proto::crypto::SignKey;
use serde_json::json;

/// Whose entries: an organisation (§19) or a person profile (§24).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Group {
    Org,
    Person,
}

impl Group {
    /// Id prefix, Lookup namespace, and the word for people.
    fn prefix(self) -> &'static str {
        if self == Group::Org { "o_" } else { "m_" }
    }

    fn ns(self) -> &'static str {
        if self == Group::Org { "org:" } else { "person:" }
    }

    fn noun(self) -> &'static str {
        if self == Group::Org { "organisation" } else { "person" }
    }

    /// The preview's id and path labels for this group.
    fn labels(self, p: &SignResponse) -> (&str, &str) {
        if self == Group::Org { (&p.org_id, &p.org_path) } else { (&p.person_id, &p.person_path) }
    }
}

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
    fn kind(self, g: Group) -> Kind {
        match (self, g) {
            (Op::Claim, Group::Org) => Kind::OrgClaimed,
            (Op::Claim, Group::Person) => Kind::PersonClaimed,
            (Op::Repo { remove: false, .. }, Group::Org) => Kind::OrgRepoAdded,
            (Op::Repo { remove: true, .. }, Group::Org) => Kind::OrgRepoRemoved,
            (Op::Repo { remove: false, .. }, Group::Person) => Kind::PersonRepoAdded,
            (Op::Repo { remove: true, .. }, Group::Person) => Kind::PersonRepoRemoved,
            (Op::Donor { revoke: false, .. }, _) => Kind::DonorApproved,
            (Op::Donor { revoke: true, .. }, _) => Kind::DonorRevoked,
        }
    }
}

/// The exact fields one signature covers, after binding.
#[derive(Clone, Debug, PartialEq, Eq)]
struct Bound {
    group: Group,
    kind: Kind,
    /// The organisation's `o_` or the person's `m_` id.
    org_id: String,
    /// ORG_REPO_*: the project's `r_` id.
    repo_id: String,
    /// Claims: this account. Approvals: the donor's pseudonym.
    subject: String,
    /// Claims: provider and the provider's numeric org id.
    claim: Option<(String, String)>,
    /// Approvals: the donor as the server confirmed it (empty until then: never signed).
    name: String,
    /// The org (or person) and the project as typed, then as the server names them.
    org: String,
    repo: String,
}

/// Check one previewed entry against the command and this account; `Err` = never sign it. Ids are
/// checked by prefix here, from the body: a Lookup that lies cannot turn a project into an org.
fn bind(g: Group, op: Op<'_>, org: &str, me: Option<&str>, p: &SignResponse) -> Result<Bound> {
    let refuse = |what: &str| usage(format!("refusing to sign: the app proposed {what}, not what you asked for"));
    let kind = Kind::from_name(&p.kind).ok_or_else(|| refuse("an unknown entry kind"))?;
    if kind != op.kind(g) {
        return Err(refuse(&format!("{} instead of {}", kind.name(), op.kind(g).name())));
    }
    let (label_id, label_path) = g.labels(p);
    if !label_path.eq_ignore_ascii_case(org) {
        return Err(refuse(&format!("{} {}", g.noun(), clean(label_path))));
    }
    let provider = org.split('/').next().unwrap_or_default();
    let b = Bound { group: g, kind, org_id: String::new(), repo_id: String::new(), subject: String::new(), claim: None, name: String::new(), org: org.into(), repo: String::new() };
    let body = parse_body(kind, &p.body_to_sign);
    // Org and person entries have the same shape: (id, provider, provider's numeric id, owner) for
    // a claim, (id, repo) for coverage.
    let claim = match body {
        Ok(Body::OrgClaim { org_id, provider, provider_org_id, owner, .. }) if g == Group::Org => Some((org_id, provider, provider_org_id, owner)),
        Ok(Body::PersonClaim { person_id, provider, provider_user_id, owner, .. }) if g == Group::Person => Some((person_id, provider, provider_user_id, owner)),
        _ => None,
    };
    let cover = match body {
        Ok(Body::OrgRepo { org_id, repo_id, .. }) if g == Group::Org => Some((org_id, repo_id)),
        Ok(Body::PersonRepo { person_id, repo_id, .. }) if g == Group::Person => Some((person_id, repo_id)),
        _ => None,
    };
    match (claim, cover, body, op) {
        (Some((id, pv, provider_id, owner)), _, _, Op::Claim) => {
            if !is_id(id, g.prefix()) || id != label_id || me != Some(owner) || pv != provider || provider_id.is_empty() || !provider_id.bytes().all(|c| c.is_ascii_digit()) {
                return Err(refuse(&format!("{} claim naming another account or {}", if g == Group::Org { "an organisation" } else { "a person" }, g.noun())));
            }
            Ok(Bound { org_id: id.into(), subject: owner.into(), claim: Some((pv.into(), provider_id.into())), name: owner.into(), ..b })
        }
        (_, Some((id, repo_id)), _, Op::Repo { repo, .. }) => {
            let same_repo = crate::config::canonical_slug(&p.repo_slug).is_some_and(|s| s.eq_ignore_ascii_case(repo));
            if !is_id(id, g.prefix()) || !is_id(repo_id, "r_") || id != label_id || repo_id != p.repo_id || !same_repo {
                return Err(refuse(&format!("an entry for another {} or project", g.noun())));
            }
            Ok(Bound { org_id: id.into(), repo_id: repo_id.into(), repo: repo.into(), ..b })
        }
        (_, _, Ok(Body::Grant { repo_id: org_id, subject, .. }), Op::Donor { donor, .. }) => {
            // A project id here would accept the donor for that project behind the org's label.
            if !is_id(org_id, g.prefix()) || org_id != label_id || org_id != p.repo_id || subject != p.subject || !subject.starts_with("ps_") {
                return Err(refuse(&format!("an approval for another {} or account", g.noun())));
            }
            // A pseudonym is matched exactly; a handle only by the server's Lookup.
            let name = if donor.starts_with("ps_") {
                if donor != subject {
                    return Err(refuse(&format!("donor {}", clean(subject))));
                }
                donor
            } else if donor.starts_with("d_") {
                return Err(usage(format!("{} accepts accounts (a handle or ps_…), not devices", if g == Group::Org { "an organisation" } else { "a person" })));
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
        let mut res = crate::link::client(ch.clone()).lookup(q.clone()).await;
        // The relay answers 30 lookups at once, then one a second: `person add` of many projects waits.
        for _ in 0..15 {
            if !matches!(&res, Err(s) if s.code() == tonic::Code::ResourceExhausted) {
                break;
            }
            tokio::time::sleep(std::time::Duration::from_millis(1100)).await;
            res = crate::link::client(ch.clone()).lookup(q.clone()).await;
        }
        match res {
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

/// Your claimed person profile when no pushed request names it (nothing covered, no sponsor yet):
/// your code-host handle on GitHub or GitLab, if the server's id for it is a profile the verified
/// key log says this account claimed.
pub(crate) fn own_profile(home: &Home) -> Option<String> {
    let cfg = home.load().ok()?;
    let handle = cfg.handle.as_deref().filter(|h| !h.is_empty())?.to_ascii_lowercase();
    owned_profile(home, &["github", "gitlab"].map(|p| format!("{p}/{handle}")))
}

/// The first of `paths` ("github/login") that the server names a claimed person profile AND the
/// verified key log says this account owns (never the server's word alone).
pub(crate) fn owned_profile(home: &Home, paths: &[String]) -> Option<String> {
    let cfg = home.load().ok()?;
    let me = cfg.pseudonym.as_deref()?;
    let rt = rt().ok()?;
    let found: Vec<(String, String)> = paths
        .iter()
        .filter_map(|path| {
            let path = path.to_ascii_lowercase();
            let l = lookup(&cfg, &rt, &format!("person:{path}"), None).ok()?;
            (is_id(&l.repo_id, "m_") && l.repo_slug.eq_ignore_ascii_case(&format!("person:{path}"))).then_some((path, l.repo_id))
        })
        .collect();
    if found.is_empty() {
        return None;
    }
    // The server names a claimed profile; the app's key-log copy may lag it (a PERSON_CLAIMED
    // signed moments ago, a busy relay): wait up to 30 s for the verified copy, never trust the
    // server's word alone.
    for attempt in 0..60 {
        if attempt > 0 {
            std::thread::sleep(std::time::Duration::from_millis(500));
        }
        let mine = crate::keylog::KeyLog::owned_people(home, &cfg, me)?;
        if let Some((path, _)) = found.iter().find(|(_, id)| mine.iter().any(|(m, _)| m == id)) {
            return Some(path.clone());
        }
    }
    None
}

/// A218: the bound entry must name what the server answered; the confirmation then shows the
/// server's names.
fn check_org(b: &mut Bound, handle: Option<&str>, l: &LookupResponse) -> Result<()> {
    let refuse = |what: String| usage(format!("refusing to sign: the app and the server disagree on {what}"));
    let path = l.repo_slug.strip_prefix(b.group.ns()).unwrap_or_default();
    if l.repo_id != b.org_id || !path.eq_ignore_ascii_case(&b.org) {
        return Err(refuse(format!("the {} ({} vs {} {})", b.group.noun(), clean(&b.org_id), clean(&l.repo_slug), clean(&l.repo_id))));
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

/// Every signed field, in words (A217), for every entry; one question for all of them (`--yes`
/// skips only the question).
fn confirm(bs: &[&Bound], signer: &str, yes: bool) -> Result<()> {
    for b in bs {
        let org = format!("the {} {} ({})", b.group.noun(), clean(&b.org), clean(&b.org_id));
        let line = match b.kind {
            Kind::OrgClaimed => format!("{} is the owner of {org}", crate::owner::your_account(&b.name, &b.subject)),
            Kind::PersonClaimed => format!("{} is {org}, for good (nobody else can ever claim it)", crate::owner::your_account(&b.name, &b.subject)),
            Kind::PersonRepoAdded => format!("your sponsors' donations may pay for your own requests on {} ({})", clean(&b.repo), clean(&b.repo_id)),
            Kind::PersonRepoRemoved => format!("your sponsors' donations no longer pay for your requests on {} ({})", clean(&b.repo), clean(&b.repo_id)),
            Kind::DonorApproved if b.group == Group::Person && !b.name.is_empty() => format!("{} may sponsor your tokens ({org}): your own requests on the repos you cover", who(b)),
            Kind::DonorRevoked if b.group == Group::Person && !b.name.is_empty() => format!("{} may no longer sponsor {org}", who(b)),
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
            eprintln!("  {} at {} (id {})", b.group.noun(), clean(prov), clean(id));
        }
    }
    eprintln!("  signed by your owner key {signer}");
    let q = if bs.len() > 1 { format!("Type yes to sign these {} entries: ", bs.len()) } else { "Type yes to sign: ".to_owned() };
    if !yes && !matches!(crate::owner::ask(&q, false)?.as_str(), "yes" | "y") {
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
        (Some((provider, provider_id)), Kind::PersonClaimed) => person_claim_body(&b.org_id, provider, provider_id, &b.subject, signer, now),
        (Some((provider, provider_org_id)), _) => org_claim_body(&b.org_id, provider, provider_org_id, &b.subject, signer, now),
        (None, Kind::OrgRepoAdded | Kind::OrgRepoRemoved) => org_repo_body(&b.org_id, &b.repo_id, signer, now),
        (None, Kind::PersonRepoAdded | Kind::PersonRepoRemoved) => person_repo_body(&b.org_id, &b.repo_id, signer, now),
        (None, _) => grant_body(&b.org_id, &b.subject, signer, now),
    }
}

/// `moochy claim --org|--person`, `moochy org|person add|remove <PROJECT>…`, `moochy
/// accept|approve <donor> --org|--person`. Several projects: every entry is checked with the
/// server first, then one confirmation and one passphrase; each is still its own signed key-log
/// entry (KEYLOG format unchanged), submitted in turn.
pub fn sign(home: &Home, g: Group, org: &str, ops: &[Op<'_>], yes: bool) -> Result<()> {
    let cfg = home.load()?;
    let rt = rt()?;
    let me = cfg.pseudonym.as_deref();
    let mut items = Vec::with_capacity(ops.len());
    for &op in ops {
        // §24.3: the relay offers no PERSON_REPO_ADDED (the owner picks the repos); both ids come
        // from the server's Lookups below, never from the app.
        if let (Group::Person, Op::Repo { repo, remove: false }) = (g, op) {
            let kind = Kind::PersonRepoAdded;
            items.push((op, Bound { group: g, kind, org_id: String::new(), repo_id: String::new(), subject: String::new(), claim: None, name: String::new(), org: org.into(), repo: repo.into() }, String::new()));
            continue;
        }
        let preview = rt.block_on(async {
            let mut c = crate::ctl::connect(&home.socket_path()).await?;
            let (org, person) = if g == Group::Org { (org.to_owned(), String::new()) } else { (String::new(), org.to_owned()) };
            let r = match op {
                Op::Claim => c.claim(ClaimRequest { org, person, dry_run: true, ..ClaimRequest::default() }).await,
                Op::Repo { repo, remove } => c.org_repo(OrgRepoRequest { org, repo: repo.into(), remove, dry_run: true, person }).await,
                Op::Donor { donor, revoke } => c.approve(ApproveRequest { org, person, donor: donor.into(), revoke, dry_run: true, ..ApproveRequest::default() }).await,
            };
            r.map(tonic::Response::into_inner).map_err(|s| if s.code() == tonic::Code::Unimplemented { usage(clean(s.message()).into_owned()) } else { status(&s) })
        })?;
        let mut b = bind(g, op, org, me, &preview)?;
        if matches!(op, Op::Claim)
            && let Some(h) = crate::owner::own_handle(&cfg, &preview.subject_username)
        {
            b.name = h;
        }
        items.push((op, b, preview.request_id));
    }
    let has_key = key_path(home, cfg.relay.as_deref()).exists();
    if !has_key {
        eprintln!("No owner key yet: one will be created (a separate key with its own passphrase) and registered in the public key log.");
        if !yes && !matches!(crate::owner::ask("Type yes to create it: ", false)?.as_str(), "yes" | "y") {
            return Err(usage("nothing signed"));
        }
    }
    let key = if has_key { load(home, cfg.relay.as_deref())? } else { register(home, &rt, None)? };
    check_own_key(home, &cfg, me, &key)?;
    check_all(&cfg, &rt, g, org, &key, &mut items)?;
    let signer = owner_key_id(&key.public());
    confirm(&items.iter().map(|(_, b, _)| b).collect::<Vec<_>>(), &signer, yes)?;
    let signed: Vec<_> = items
        .into_iter()
        .map(|(_, b, id)| {
            let body = body(&b, &signer, now_ms());
            let sig = key.sign(&sig_message(b.kind, &body));
            (b, id, body, sig)
        })
        .collect();
    drop(key);
    // Each entry on its own: one the relay refuses (say, a role it no longer sees) does not stop
    // the others; the first refusal is the command's error.
    let mut first_err = None;
    for (b, id, body, sig) in signed {
        let done = match rt.block_on(submit(home, SubmitEntryRequest { request_id: id, kind: b.kind.name().into(), body, sigs: vec![sig.to_vec()] })) {
            Ok(d) => d,
            Err(e) => {
                eprintln!("{} {}: not signed: {e}", b.kind.name(), clean(if b.repo.is_empty() { &b.org } else { &b.repo }));
                first_err.get_or_insert(e);
                continue;
            }
        };
        let (k_path, k_id) = if g == Group::Org { ("org", "org_id") } else { ("person", "person_id") };
        crate::util::emit(&json!({"request_id": done.request_id, "kind": b.kind.name(), k_path: b.org, k_id: b.org_id, "repo": b.repo, "repo_id": b.repo_id,
            "subject": b.subject, "subject_username": b.name, "signer": done.signer, "issued_at_ms": done.issued_at_ms, "signed": done.signed, "log_index": done.log_index}));
    }
    first_err.map_or(Ok(()), Err)
}

/// A218: every entry's ids checked with the server (dialed directly, never through the app); a
/// person's PERSON_REPO_ADDED takes both ids from it.
fn check_all(cfg: &crate::config::Config, rt: &tokio::runtime::Runtime, g: Group, org: &str, key: &SignKey, items: &mut [(Op<'_>, Bound, String)]) -> Result<()> {
    let me = cfg.pseudonym.as_deref();
    let org_slug = format!("{}{org}", g.ns());
    let mut org_l = None; // one Lookup of the org (or person) for all its projects
    for (op, b, _) in items.iter_mut() {
        match *op {
            // Like a project claim: the org is not claimed yet, the body names this account.
            Op::Claim => {}
            Op::Repo { repo, .. } => {
                if org_l.is_none() {
                    org_l = Some(lookup(cfg, rt, &org_slug, None)?);
                }
                let l = org_l.as_ref().ok_or_else(|| internal("lookup"))?;
                if b.org_id.is_empty() {
                    if !is_id(&l.repo_id, g.prefix()) {
                        return Err(usage(format!("refusing to sign: the server named another {} ({})", g.noun(), clean(&l.repo_id))));
                    }
                    b.org_id.clone_from(&l.repo_id);
                }
                check_org(b, None, l)?;
                let lr = lookup(cfg, rt, repo, None).map_err(|e| {
                    if g == Group::Person && e.exit == crate::util::Exit::Usage {
                        usage(format!("refusing to sign: the Moochy server knows no public repo you maintain named {} (sign in on the web again so your code host can confirm your role)", clean(repo)))
                    } else {
                        e
                    }
                })?;
                if b.repo_id.is_empty() {
                    if !is_id(&lr.repo_id, "r_") {
                        return Err(usage(format!("refusing to sign: the server named something else than a project for {}", clean(repo))));
                    }
                    b.repo_id.clone_from(&lr.repo_id);
                }
                check_repo(b, &lr)?;
                eprintln!("Checked with the Moochy server (not through the app): {} is {}; {} is {}", clean(&b.org), clean(&b.org_id), clean(&b.repo), clean(&b.repo_id));
            }
            Op::Donor { donor, .. } => {
                let handle = (!donor.starts_with("ps_")).then_some(donor);
                let who = match (handle, me) {
                    (Some(h), Some(me)) => Some((h, me, key)),
                    (Some(_), None) => return Err(auth("not logged in: run `moochy login` first")),
                    _ => None,
                };
                check_org(b, handle, &lookup(cfg, rt, &org_slug, who)?)?;
                let person = handle.map(|h| format!("; {} is {}", clean(h), clean(&b.subject))).unwrap_or_default();
                eprintln!("Checked with the Moochy server (not through the app): {} is {}{person}", clean(&b.org), clean(&b.org_id));
            }
        }
    }
    Ok(())
}

#[derive(serde::Deserialize)]
struct OrgInfo {
    /// The people API names it `person_id` (§24.6).
    #[serde(alias = "person_id")]
    org_id: String,
    path: String,
    #[serde(default)]
    repos: Vec<Covered>,
    /// Owner view only: covered in the key log, but the server no longer serves them (§24.3: role
    /// lost or repo made private at a re-check; §19: dropped). Never listed as covered.
    #[serde(skip)]
    dropped: Vec<String>,
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
/// `moochy person list` (§24.6): the same for the repos a person profile covers.
pub fn list(home: &Home, g: Group, org: &str, json_out: bool) -> Result<()> {
    let cfg = home.load()?;
    let mut info = match owned(home, &cfg, g, org) {
        Ok(Some(i)) => i,
        // The server does not know the org: the public API would not either.
        Err(e) if e.exit == crate::util::Exit::Usage => return Err(e),
        _ => public(&cfg, g, org)?,
    };
    for r in info.repos.iter_mut().filter(|r| !r.slug.is_empty()) {
        r.slug = qualified(&r.slug);
    }
    for id in &info.dropped {
        eprintln!("note: {} ({}) is no longer served by the server (maintainer role lost, made private, or removed): not listed, though your key log still names it", clean(id), clean(&info.path));
    }
    if json_out && g == Group::Person {
        crate::util::emit(&json!({"person": info.path, "person_id": info.org_id, "repos": info.repos, "dropped": info.dropped}));
    } else if json_out {
        crate::util::emit(&json!({"org": info.path, "org_id": info.org_id, "repos": info.repos, "dropped": info.dropped}));
    } else if info.repos.is_empty() && g == Group::Person {
        println!("{} ({}) covers no repo yet: moochy person add <PROJECT>", clean(&info.path), clean(&info.org_id));
    } else if info.repos.is_empty() {
        println!("{} ({}) funds none of your projects yet: moochy org add <PROJECT> --org {}", clean(&info.path), clean(&info.org_id), clean(&info.path));
    } else {
        let verb = if g == Group::Person { "Sponsorships of" } else { "Donations to" };
        println!("{verb} {} ({}) fund:", clean(&info.path), clean(&info.org_id));
        for r in &info.repos {
            if r.slug.is_empty() {
                println!("  {} (name not yet pushed by the server)", clean(&r.repo_id));
            } else {
                println!("  {} ({})", clean(&r.slug), clean(&r.repo_id));
            }
        }
    }
    Ok(())
}

/// A project as CONTRACT §9 names it canonically: the legacy `owner/name` form is GitHub, shown as
/// `github/owner/name` like the org it belongs to; provider-qualified slugs stay as they are.
fn qualified(slug: &str) -> String {
    if slug.split('/').count() == 2 { format!("github/{slug}") } else { slug.to_owned() }
}

/// The owner's view (WIRING §4). `Ok(None)`: not this account's org in the key log.
fn owned(home: &Home, cfg: &crate::config::Config, g: Group, org: &str) -> Result<Option<OrgInfo>> {
    let Some(me) = cfg.pseudonym.as_deref() else { return Ok(None) };
    let rt = rt()?;
    // The org id from the server (dialed directly), never from the app's list.
    let l = lookup(cfg, &rt, &format!("{}{org}", g.ns()), None).map_err(|e| if e.exit == crate::util::Exit::Usage { usage(format!("the server knows no claimed {} {}", g.noun(), clean(org))) } else { e })?;
    let path = l.repo_slug.strip_prefix(g.ns()).unwrap_or_default();
    if !is_id(&l.repo_id, g.prefix()) || !path.eq_ignore_ascii_case(org) {
        return Err(internal(format!("the server answered for another {}", g.noun())));
    }
    // A270: the verified key log decides what is listed (ORG_CLAIMED by this account, ORG_REPO_ADDED
    // active, the project claimed by this account too); the relay's push only names the rows.
    // The node writes each pushed checkpoint to its copy within moments, and the relay re-pushes its
    // offers after each entry: a fresh claim, cover or removal one side does not show yet gets a few
    // seconds before the push and the log are called in disagreement. ponytail: a non-owner pays
    // the 5 s before the public API; waiting on the mirror's size needs it on node.sock.
    let (mut covered, mut rows) = (None, Vec::new());
    for attempt in 0..=10 {
        if attempt > 0 {
            std::thread::sleep(std::time::Duration::from_millis(500));
        }
        let pushed = rt.block_on(async {
            let mut c = crate::ctl::connect(&home.socket_path()).await?;
            c.pending(crate::pb::local::PendingRequest {}).await.map(tonic::Response::into_inner).map_err(|s| status(&s))
        })?;
        let remove = Op::Repo { repo: "", remove: true }.kind(g);
        rows = pushed.requests.into_iter().filter(|q| q.kind == remove.name() && g.labels(q).0 == l.repo_id).collect();
        let owned = if g == Group::Org { crate::keylog::KeyLog::owned_orgs(home, cfg, me) } else { crate::keylog::KeyLog::owned_people(home, cfg, me) };
        let Some(orgs) = owned else { return Ok(None) };
        covered = orgs.into_iter().find(|(o, _)| *o == l.repo_id).map(|(_, r)| r);
        if covered.as_ref().is_some_and(|c| c.len() == rows.len() && rows.iter().all(|q| c.contains(&q.repo_id))) {
            break;
        }
    }
    let Some(covered) = covered else { return Ok(None) };
    // A `person-repo-dropped:` offer asks the owner to sign the removal of a repo the relay already
    // dropped (§24.3 re-check): it names the repo, but the repo is no longer served (E128).
    let named = |id: &str| rows.iter().find(|q| q.repo_id == id && !q.request_id.starts_with("person-repo-dropped:")).map(|q| q.repo_slug.clone());
    for q in rows.iter().filter(|q| !covered.contains(&q.repo_id)) {
        eprintln!("warning: the server lists {} ({}) as funded by {}, but your key log does not: not listed", clean(&q.repo_slug), clean(&q.repo_id), clean(path));
    }
    // The relay offers a removal for every repo it still serves; one it dropped (CONTRACT §24.3: a
    // re-check found no maintainer role or a private repo) has no offer and is not listed.
    // ponytail: a dropped repo makes every owner list wait out the 5 s agreement loop above.
    let (repos, dropped): (Vec<String>, Vec<String>) = covered.into_iter().partition(|id| named(id).is_some());
    let repos = repos.into_iter().map(|repo_id| Covered { slug: named(&repo_id).unwrap_or_default(), repo_id }).collect();
    Ok(Some(OrgInfo { org_id: l.repo_id.clone(), path: path.to_owned(), repos, dropped }))
}

/// Anyone's view: the server's public orgs API, on an origin that serves HTTP.
fn public(cfg: &crate::config::Config, g: Group, org: &str) -> Result<OrgInfo> {
    let relay = crate::tls::Origin::parse(cfg.relay.as_deref().unwrap_or(crate::config::DEFAULT_RELAY))?;
    let api = if g == Group::Org { "orgs" } else { "people" };
    let f = moochy_keylog::fetch::Fetcher::with_roots(&format!("{}/api/v1/{api}/", relay.url()), std::time::Duration::from_secs(20), crate::tls::roots(cfg.ca_file.as_deref())?)
        .map_err(|e| internal(format!("orgs API: {e}")))?;
    let raw = f.get(org, 256 * 1024).map_err(|e| {
        let e = e.to_string();
        if e.contains(" 404") {
            usage(format!("the server knows no claimed {} {} (or it does not support them yet)", g.noun(), clean(org)))
        } else {
            crate::util::net(format!("could not read {} {} from the server: {}", g.noun(), clean(org), clean(&e)))
        }
    })?;
    let info: OrgInfo = serde_json::from_slice(&raw).map_err(|_| internal(format!("the server's {} answer is not the expected JSON", g.noun())))?;
    if !is_id(&info.org_id, g.prefix()) || !info.path.eq_ignore_ascii_case(org) || info.repos.iter().any(|r| !is_id(&r.repo_id, "r_")) {
        return Err(internal(format!("the server answered for another {}", g.noun())));
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
        let b = bind(Group::Org, Op::Claim, "github/acme", Some(ME), &ok).unwrap();
        assert_eq!(b.claim, Some(("github".into(), "900".into())));
        // Rebuilt with our signer and time, the body still says the same thing.
        assert!(matches!(parse_body(Kind::OrgClaimed, &body(&b, OK, 2)), Ok(Body::OrgClaim { org_id: ORG, owner: ME, provider_org_id: "900", .. })));
        assert!(bind(Group::Org, Op::Claim, "github/acme", Some(ME), &resp("ORG_CLAIMED", "", ALICE, org_claim_body(ORG, "github", "900", ALICE, OK, 1))).is_err(), "another owner");
        assert!(bind(Group::Org, Op::Claim, "github/acme", Some(ME), &resp("ORG_CLAIMED", "", ME, org_claim_body(ORG, "gitlab", "900", ME, OK, 1))).is_err(), "gitlab group behind github/");
        assert!(bind(Group::Org, Op::Claim, "github/acme", Some(ME), &resp("ORG_CLAIMED", "", ME, org_claim_body(R, "github", "900", ME, OK, 1))).is_err(), "a project id");
        assert!(bind(Group::Org, Op::Claim, "github/evil", Some(ME), &ok).is_err(), "label of another org");
        assert!(bind(Group::Org, Op::Claim, "github/acme", None, &ok).is_err(), "unknown account");
        let mut wrong = ok.clone();
        wrong.org_id = OTHER.into();
        assert!(bind(Group::Org, Op::Claim, "github/acme", Some(ME), &wrong).is_err(), "label id differs from body");
    }

    #[test]
    fn repo_entries_bind_both_ids() {
        let mut p = resp("ORG_REPO_ADDED", R, "", org_repo_body(ORG, R, OK, 1));
        p.repo_slug = "acme/app1".into();
        let add = Op::Repo { repo: "acme/app1", remove: false };
        let mut b = bind(Group::Org, add, "github/acme", Some(ME), &p).unwrap();
        assert!(bind(Group::Org, Op::Repo { repo: "acme/app1", remove: true }, "github/acme", Some(ME), &p).is_err(), "kind");
        assert!(bind(Group::Org, Op::Repo { repo: "acme/side", remove: false }, "github/acme", Some(ME), &p).is_err(), "another project");
        let swapped = resp("ORG_REPO_ADDED", R, "", org_repo_body(R, ORG, OK, 1));
        assert!(bind(Group::Org, add, "github/acme", Some(ME), &swapped).is_err(), "ids swapped");
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
        assert!(bind(Group::Org, approve("alice"), "github/acme", Some(ME), &proj).is_err());
        assert!(bind(Group::Org, approve(ME), "github/acme", Some(ME), &p).is_err(), "pseudonym mismatch");
        assert!(bind(Group::Org, approve("d_x"), "github/acme", Some(ME), &p).is_err(), "devices");
        let b = bind(Group::Org, approve(ALICE), "github/acme", Some(ME), &p).unwrap();
        assert_eq!(b.name, ALICE);
        // A handle: unconfirmed (never signed) until the server's Lookup says who it is.
        let mut b = bind(Group::Org, approve("alice"), "github/acme", Some(ME), &p).unwrap();
        assert!(confirm(&[&b], OK, true).is_err());
        let l = LookupResponse { repo_slug: "org:github/acme".into(), repo_id: ORG.into(), handle: "alice".into(), pseudonym: ALICE.into() };
        assert!(check_org(&mut b.clone(), Some("alice"), &LookupResponse { pseudonym: ME.into(), ..l.clone() }).is_err(), "the server names another account");
        check_org(&mut b, Some("alice"), &l).unwrap();
        assert_eq!(b.name, "alice");
        assert!(matches!(parse_body(Kind::DonorApproved, &body(&b, OK, 2)), Ok(Body::Grant { repo_id: ORG, subject: ALICE, .. })));
    }

    #[test]
    fn listed_projects_are_provider_qualified() {
        assert_eq!(qualified("acme/app1"), "github/acme/app1");
        assert_eq!(qualified("github/acme/app1"), "github/acme/app1");
        assert_eq!(qualified("gitlab/grp/sub/tool"), "gitlab/grp/sub/tool");
    }

    #[test]
    fn person_entries_bind_an_m_id_never_an_org() {
        const M: &str = "m_01ARZ3NDEKTSV4RRFFQ69G5FAV";
        let pr = |kind: &str, repo_id: &str, subject: &str, body: Vec<u8>| SignResponse {
            kind: kind.into(),
            repo_id: repo_id.into(),
            subject: subject.into(),
            body_to_sign: body,
            person_id: M.into(),
            person_path: "github/alice".into(),
            ..SignResponse::default()
        };
        let p = Group::Person;
        // Claim: this account, the typed provider, a numeric provider user id.
        let ok = pr("PERSON_CLAIMED", "", ME, person_claim_body(M, "github", "4242", ME, OK, 1));
        let b = bind(p, Op::Claim, "github/alice", Some(ME), &ok).unwrap();
        assert!(matches!(parse_body(Kind::PersonClaimed, &body(&b, OK, 2)), Ok(Body::PersonClaim { person_id: M, owner: ME, provider_user_id: "4242", .. })));
        assert!(bind(p, Op::Claim, "github/alice", Some(ME), &pr("PERSON_CLAIMED", "", ALICE, person_claim_body(M, "github", "4242", ALICE, OK, 1))).is_err(), "another account");
        assert!(bind(p, Op::Claim, "github/bob", Some(ME), &ok).is_err(), "label of another person");
        assert!(bind(p, Op::Claim, "github/alice", Some(ME), &pr("ORG_CLAIMED", "", ME, org_claim_body(ORG, "github", "4242", ME, OK, 1))).is_err(), "an org claim behind a person");
        assert!(bind(Group::Org, Op::Claim, "github/alice", Some(ME), &ok).is_err(), "a person claim behind an org");
        // Coverage: both ids, the typed repo, and the server must agree on the person (person: namespace).
        let mut cov = pr("PERSON_REPO_ADDED", R, "", person_repo_body(M, R, OK, 1));
        cov.repo_slug = "alice/tool".into();
        let add = Op::Repo { repo: "alice/tool", remove: false };
        let mut b = bind(p, add, "github/alice", Some(ME), &cov).unwrap();
        assert!(bind(p, Op::Repo { repo: "alice/other", remove: false }, "github/alice", Some(ME), &cov).is_err());
        assert!(bind(p, add, "github/alice", Some(ME), &pr("PERSON_REPO_ADDED", R, "", person_repo_body(ORG, R, OK, 1))).is_err(), "an org id");
        let l = LookupResponse { repo_slug: "person:github/alice".into(), repo_id: M.into(), ..LookupResponse::default() };
        assert!(check_org(&mut b.clone(), None, &LookupResponse { repo_slug: "org:github/alice".into(), ..l.clone() }).is_err(), "an org answer");
        check_org(&mut b, None, &l).unwrap();
        assert!(matches!(parse_body(Kind::PersonRepoAdded, &body(&b, OK, 2)), Ok(Body::PersonRepo { person_id: M, repo_id: R, .. })));
        // Approval of a sponsor on the m_ id.
        let g = pr("DONOR_APPROVED", M, ALICE, grant_body(M, ALICE, OK, 1));
        let b = bind(p, Op::Donor { donor: ALICE, revoke: false }, "github/alice", Some(ME), &g).unwrap();
        assert!(matches!(parse_body(Kind::DonorApproved, &body(&b, OK, 2)), Ok(Body::Grant { repo_id: M, subject: ALICE, .. })));
        assert!(bind(p, Op::Donor { donor: ALICE, revoke: false }, "github/alice", Some(ME), &pr("DONOR_APPROVED", R, ALICE, grant_body(R, ALICE, OK, 1))).is_err(), "a project grant behind the person");
    }
}
