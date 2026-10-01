//! `mask::glob1` against the recursive definition of a `*` glob.
#![no_main]
libfuzzer_sys::fuzz_target!(|data: &[u8]| moochy_sandbox::fuzzing::mask_glob(data));
