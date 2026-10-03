//! `cargo run -p moochy-tui --example demo -- [--snapshot 80x24 --keys "2jj"] [--theme light] [--ascii]`
//! — the dashboard on fixtures, before (and besides) the `moochy tui --demo` entry.

use std::process::ExitCode;

fn main() -> ExitCode {
    let args: Vec<String> = std::env::args().skip(1).collect();
    let opts = match moochy_tui::Options::parse(&args) {
        Ok(o) => o,
        Err(e) => {
            eprintln!("{e}");
            return ExitCode::from(2);
        }
    };
    let mut src = moochy_tui::fixture_source(&opts);
    let r = if opts.snapshot.is_some() {
        moochy_tui::snapshot(&mut src, &opts).map(|s| print!("{s}"))
    } else {
        moochy_tui::run(Box::new(src), None, &opts)
    };
    match r {
        Ok(()) => ExitCode::SUCCESS,
        Err(e) => {
            eprintln!("moochy tui: {e}");
            ExitCode::FAILURE
        }
    }
}
