//! Single-use request validators (CONTRACT §15.2): the only place a stranger's request bytes are
//! parsed (decompression + strict JSON + firewall + route check) is a jailed child that holds no
//! keys, no files and no network, and serves exactly one request.
//!
//! The background process cannot exec after its lockdown, and forking it would copy its keys into
//! the child. So, before the lockdown, it execs one **key-less zygote** (`moochy
//! __validate-zygote`, clean environment, no inherited fd but its control socket), which locks
//! itself down and forks the jailed single-use children with `moochy_sandbox::spawn_validator_with`.
//! Each child's socket is passed back to the node (SCM_RIGHTS), which talks to the child directly
//! (`moochy_worker::validate::validate_on`): no extra copy through the zygote, any number of
//! validations in parallel. Two children are kept warm, so a request never waits for a fork.

use crate::node::lock;
use crate::util::log;
use moochy_worker::validate::{Validated, ValidateError, ValidateRequest};
use serde_json::json;
use std::io::{IoSlice, IoSliceMut, Read as _, Write as _};
use std::mem::MaybeUninit;
use std::os::fd::AsFd as _;
use std::os::unix::net::UnixStream;
use std::path::PathBuf;
use std::sync::{Arc, Mutex};
use std::time::Duration;

const ARG: &str = "__validate-zygote";
const WARM: usize = 2;
/// Whole request: write, child work, read (moochy-worker's suggested deadline).
const DEADLINE: Duration = Duration::from_secs(5);

// ---------------------------------------------------------------- zygote (its own process)

/// `moochy __validate-zygote`: run before anything else in `main` (no config, no keystore,
/// no logging to files). `None` = not the zygote.
pub fn zygote_entry() -> Option<u8> {
    let mut a = std::env::args_os().skip(1);
    if a.next()? != ARG {
        return None;
    }
    Some(match zygote() {
        Ok(()) => 0,
        Err(e) => {
            eprintln!("moochy validator zygote: {e}");
            1
        }
    })
}

fn zygote() -> std::io::Result<()> {
    // fd 0 is the control socket to the node (the only fd it gave us).
    let ctl = UnixStream::from(std::io::stdin().as_fd().try_clone_to_owned()?);
    // Same cage as the node, minus everything: no state dir (only `/dev/null`, which each child
    // reopens for its stdio before jailing itself), no file to read, no port.
    let mut p = moochy_sandbox::DonorPolicy::new(PathBuf::from("/dev/null"), 0);
    p.ro_paths.clear();
    lockdown(&p)?;
    let mut cmd = [0u8; 1];
    loop {
        // Reap finished children (single-use: each exits after its one request).
        while let Ok(Some(_)) = rustix::process::waitpid(None, rustix::process::WaitOptions::NOHANG) {}
        match (&ctl).read(&mut cmd) {
            Ok(1) => {}
            _ => return Ok(()), // node gone
        }
        let v = moochy_sandbox::spawn_validator_with(|ch| moochy_worker::validate::child_main(&ch, &ch)).map_err(std::io::Error::other)?;
        let fds = [v.sock.as_fd()];
        let mut space = [MaybeUninit::uninit(); rustix::cmsg_space!(ScmRights(1))];
        let mut anc = rustix::net::SendAncillaryBuffer::new(&mut space);
        anc.push(rustix::net::SendAncillaryMessage::ScmRights(&fds));
        rustix::net::sendmsg(&ctl, &[IoSlice::new(b"V")], &mut anc, rustix::net::SendFlags::empty())?;
        // Our copy of the parent end closes here; the child is reaped later.
    }
}

#[cfg(any(target_os = "linux", target_os = "macos"))]
fn lockdown(p: &moochy_sandbox::DonorPolicy) -> std::io::Result<()> {
    // The zygote cage, not the donor one: on macOS the donor profile denies fork, and a
    // stricter profile cannot be stacked in each child (A219).
    moochy_sandbox::lockdown_zygote(p).map(drop).map_err(std::io::Error::other)
}

#[cfg(not(any(target_os = "linux", target_os = "macos")))]
fn lockdown(_: &moochy_sandbox::DonorPolicy) -> std::io::Result<()> {
    Err(std::io::Error::other("no validator sandbox on this OS yet"))
}

// ---------------------------------------------------------------- node side

/// The node's handle on the zygote and its warm children.
pub struct Pool {
    /// The zygote is gone: no validator can ever be made again in this process (exec is denied
    /// after the lockdown), so the worker stops offering until the app restarts.
    dead: std::sync::atomic::AtomicBool,
    ctl: Mutex<UnixStream>,
    idle: Mutex<Vec<UnixStream>>,
    _zygote: Mutex<std::process::Child>,
}

impl Pool {
    /// Exec the zygote. Call before the node locks itself down (exec is denied afterwards).
    pub fn spawn() -> std::io::Result<Self> {
        let (ours, theirs) = UnixStream::pair()?;
        let child = std::process::Command::new(std::env::current_exe()?)
            .arg(ARG)
            .env_clear()
            .stdin(std::process::Stdio::from(std::os::fd::OwnedFd::from(theirs)))
            .stdout(std::process::Stdio::null())
            .stderr(std::process::Stdio::null())
            .spawn()?;
        ours.set_read_timeout(Some(DEADLINE))?;
        ours.set_write_timeout(Some(DEADLINE))?;
        Ok(Self { dead: std::sync::atomic::AtomicBool::new(false), ctl: Mutex::new(ours), idle: Mutex::new(Vec::with_capacity(WARM)), _zygote: Mutex::new(child) })
    }

    pub fn alive(&self) -> bool {
        !self.dead.load(std::sync::atomic::Ordering::Relaxed)
    }

    /// One fresh child from the zygote (blocking: a fork + one round trip).
    fn fetch(&self) -> std::io::Result<UnixStream> {
        let r = self.fetch_inner();
        if r.is_err() {
            self.dead.store(true, std::sync::atomic::Ordering::Relaxed);
        }
        r
    }

    fn fetch_inner(&self) -> std::io::Result<UnixStream> {
        let ctl = lock(&self.ctl);
        (&*ctl).write_all(b"F")?;
        let mut byte = [0u8; 1];
        let mut space = [MaybeUninit::uninit(); rustix::cmsg_space!(ScmRights(1))];
        let mut anc = rustix::net::RecvAncillaryBuffer::new(&mut space);
        // MSG_CMSG_CLOEXEC is Linux-only; elsewhere the flag is set right after the receive (the
        // background process never execs after its lockdown, so the window is harmless).
        #[cfg(target_os = "linux")]
        let flags = rustix::net::RecvFlags::CMSG_CLOEXEC;
        #[cfg(not(target_os = "linux"))]
        let flags = rustix::net::RecvFlags::empty();
        rustix::net::recvmsg(&*ctl, &mut [IoSliceMut::new(&mut byte)], &mut anc, flags)?;
        for m in anc.drain() {
            if let rustix::net::RecvAncillaryMessage::ScmRights(mut fds) = m
                && let Some(fd) = fds.next()
            {
                #[cfg(not(target_os = "linux"))]
                rustix::io::fcntl_setfd(&fd, rustix::io::FdFlags::CLOEXEC)?;
                return Ok(UnixStream::from(fd));
            }
        }
        Err(std::io::Error::other("zygote sent no validator"))
    }

    /// Fill the warm set (blocking; startup and after each take, on a blocking thread).
    pub fn fill(&self) {
        loop {
            if lock(&self.idle).len() >= WARM {
                return;
            }
            match self.fetch() {
                Ok(s) => lock(&self.idle).push(s),
                Err(e) => {
                    // ponytail: the zygote cannot be re-exec'd after the lockdown; the worker
                    // stops offering (`can_serve`). Restart the app to recover.
                    log("error", "request validator unavailable: not donating until the app restarts", &json!({"error": e.to_string()}));
                    return;
                }
            }
        }
    }

    /// Validate one request in a fresh jailed child. Child failures are `busy` (retryable).
    pub async fn validate(self: &Arc<Self>, req: &ValidateRequest<'_>) -> Result<Validated, ValidateError> {
        let warm = lock(&self.idle).pop();
        let s = if let Some(s) = warm {
            s
        } else {
            let me = self.clone();
            tokio::task::spawn_blocking(move || me.fetch()).await.map_err(|_| ValidateError::Child("spawn"))?.map_err(|_| ValidateError::Child("spawn"))?
        };
        let me = self.clone();
        tokio::task::spawn_blocking(move || me.fill());
        s.set_nonblocking(true).map_err(|_| ValidateError::Child("socket"))?;
        let s = tokio::net::UnixStream::from_std(s).map_err(|_| ValidateError::Child("socket"))?;
        moochy_worker::validate::validate_on(s, req, DEADLINE).await
    }
}
