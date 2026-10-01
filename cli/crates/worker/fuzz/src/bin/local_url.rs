//! Local inference server base-URL vetting (`provider::check_local_base_url`). Invariants: no
//! panic; vetted (strict) acceptance implies unvetted acceptance with the same class; nothing
//! accepted in either mode resolves to link-local / metadata / unspecified / multicast.
#![no_main]
use libfuzzer_sys::fuzz_target;
use moochy_worker::provider::{LocalHost, check_local_base_url};
use std::net::IpAddr;

fn host(url: &str) -> Option<&str> {
    let rest = url.split_once("://")?.1;
    let rest = rest.strip_suffix('/').unwrap_or(rest);
    Some(match rest.strip_prefix('[') {
        Some(r) => r.split_once(']')?.0,
        None => rest.rsplit_once(':').map_or(rest, |(h, _)| h),
    })
}

fuzz_target!(|data: &[u8]| {
    let Ok(url) = std::str::from_utf8(data) else { return };
    let strict = check_local_base_url(url, false);
    let loose = check_local_base_url(url, true);
    if let Ok(c) = strict {
        assert!(matches!(c, LocalHost::Loopback | LocalHost::Lan));
        assert_eq!(loose.clone().map_err(|e| e.0), Ok(c));
    }
    if loose.is_ok() {
        if let Some(ip) = host(url).and_then(|h| h.parse::<IpAddr>().ok()) {
            let ip = match ip {
                IpAddr::V6(v6) => v6.to_ipv4_mapped().map_or(IpAddr::V6(v6), IpAddr::V4),
                v4 => v4,
            };
            assert!(!ip.is_unspecified() && !ip.is_multicast(), "{url}");
            match ip {
                IpAddr::V4(v4) => assert!(!v4.is_link_local() && !v4.is_broadcast(), "{url}"),
                IpAddr::V6(v6) => assert!(v6.segments()[0] & 0xffc0 != 0xfe80, "{url}"),
            }
        }
    }
});
