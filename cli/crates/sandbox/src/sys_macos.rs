//! The only `unsafe` on macOS (CONTRACT §15 exception): `sandbox_init(3)` FFI,
//! `fork` and `_exit`. Everything else on macOS uses `std`/`Command`.
#![allow(unsafe_code)]

use std::ffi::CString;
use std::io;

#[link(name = "sandbox")]
unsafe extern "C" {
    fn sandbox_init(profile: *const libc::c_char, flags: u64, errorbuf: *mut *mut libc::c_char)
        -> libc::c_int;
    fn sandbox_free_error(errorbuf: *mut libc::c_char);
}

/// Apply an SBPL profile string to the current process. Irreversible.
pub fn sandbox_init_apply(profile: &str) -> io::Result<()> {
    let c = CString::new(profile).map_err(|_| io::Error::other("profile has NUL"))?;
    let mut err: *mut libc::c_char = std::ptr::null_mut();
    // SAFETY: `c` is a valid NUL-terminated C string for the call; `err` is a
    // valid out-pointer we free via sandbox_free_error.
    let r = unsafe { sandbox_init(c.as_ptr(), 0, &mut err) };
    if r == 0 {
        Ok(())
    } else {
        let msg = if err.is_null() {
            "sandbox_init failed".to_string()
        } else {
            // SAFETY: err points to a C string allocated by libsandbox.
            let s = unsafe { std::ffi::CStr::from_ptr(err) }
                .to_string_lossy()
                .into_owned();
            // SAFETY: free the libsandbox-allocated error buffer.
            unsafe { sandbox_free_error(err) };
            s
        };
        Err(io::Error::other(msg))
    }
}

/// Public name used by `macos.rs`.
pub use sandbox_init_apply as sandbox_init;

pub enum Fork {
    Parent(i32),
    Child,
}

pub fn fork() -> io::Result<Fork> {
    // SAFETY: fork reads/writes no user memory; child-side contract per module.
    let pid = unsafe { libc::fork() };
    match pid {
        -1 => Err(io::Error::last_os_error()),
        0 => Ok(Fork::Child),
        n => Ok(Fork::Parent(n)),
    }
}

pub fn exit_immediately(code: i32) -> ! {
    // SAFETY: _exit never returns and touches no user memory.
    unsafe { libc::_exit(code) }
}

/// Wait for a child pid; return exit code (128 + signal if killed).
pub fn wait_raw(pid: i32) -> io::Result<i32> {
    let mut status: libc::c_int = 0;
    loop {
        // SAFETY: waitpid writes only into `status`.
        let r = unsafe { libc::waitpid(pid, &mut status, 0) };
        if r == -1 {
            let e = io::Error::last_os_error();
            if e.raw_os_error() == Some(libc::EINTR) {
                continue;
            }
            return Err(e);
        }
        if libc::WIFEXITED(status) {
            return Ok(libc::WEXITSTATUS(status));
        }
        if libc::WIFSIGNALED(status) {
            return Ok(128i32.saturating_add(libc::WTERMSIG(status)));
        }
    }
}
