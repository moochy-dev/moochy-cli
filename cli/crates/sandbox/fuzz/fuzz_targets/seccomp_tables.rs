//! The compiled agent / donor / validator seccomp programs, run by a cBPF
//! interpreter on arbitrary `seccomp_data`, against the policy (Linux only).
#![no_main]
libfuzzer_sys::fuzz_target!(|data: &[u8]| moochy_sandbox::fuzzing::seccomp_tables(data));
