//! Stand-alone request validator child (CONTRACT §15.2), the same entry point as
//! `moochy __validate`: used by this crate's tests and by moochy-sandbox's lockdown tests.
#![forbid(unsafe_code)]

fn main() {
    std::process::exit(moochy_worker::validate::child_main(std::io::stdin().lock(), std::io::stdout().lock()));
}
