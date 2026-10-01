//! The committed `spec/vectors/*.json` must be exactly what the library produces today.
//! Regenerate with `cargo run -p moochy-proto --example vecgen -- ../spec/vectors` (from `cli/`).
#![allow(clippy::pedantic, clippy::unwrap_used, clippy::expect_used, clippy::panic, clippy::indexing_slicing, clippy::arithmetic_side_effects)]

#[path = "../examples/vecgen/gen.rs"]
mod r#gen;

#[test]
fn committed_vectors_match_library() {
    let dir = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("../../../spec/vectors");
    for (name, v) in r#gen::all() {
        let want = r#gen::render(&v);
        let got = std::fs::read_to_string(dir.join(name)).unwrap_or_default();
        assert!(got == want, "spec/vectors/{name} is stale: regenerate with the vecgen example");
    }
}

fn vector(name: &str) -> serde_json::Value {
    let p = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("../../../spec/vectors").join(name);
    serde_json::from_str(&std::fs::read_to_string(p).unwrap()).unwrap()
}

/// CONTRACT R7: the reserved list lives in usernames.json; the Rust copy must be identical.
#[test]
fn reserved_list_matches_vector_file() {
    let v = vector("usernames.json");
    let file: Vec<&str> = v["reserved"].as_array().unwrap().iter().map(|x| x.as_str().unwrap()).collect();
    assert_eq!(file, moochy_proto::username::RESERVED, "spec/vectors/usernames.json `reserved` != username::RESERVED");
    for r in &file {
        assert_eq!(*r, r.to_ascii_lowercase());
        assert_ne!(moochy_proto::username::verdict(r, |_| false, |_| false), moochy_proto::username::Verdict::Ok, "{r}");
    }
    for c in v["cases"].as_array().unwrap() {
        let input = c["input"].as_str().unwrap();
        let taken = |h: &str| v["taken"].as_array().unwrap().iter().any(|x| x == h);
        let tomb = |h: &str| v["tombstoned"].as_array().unwrap().iter().any(|x| x == h);
        assert_eq!(moochy_proto::username::verdict(input, taken, tomb).as_str(), c["verdict"], "{input:?}");
        assert_eq!(moochy_proto::username::canonical(input).ok().as_deref(), c["canonical"].as_str(), "{input:?}");
    }
}

/// Every id-shaped string in every vector file parses with the real parser, unless it sits
/// under a key that marks it as a negative case (`*invalid*`, `*rejected*`).
#[test]
fn every_listed_id_parses() {
    fn walk(v: &serde_json::Value, negative: bool, seen: &mut usize) {
        match v {
            serde_json::Value::Object(m) => {
                for (k, x) in m {
                    walk(x, negative || k.contains("invalid") || k.contains("rejected"), seen);
                }
            }
            serde_json::Value::Array(a) => a.iter().for_each(|x| walk(x, negative, seen)),
            serde_json::Value::String(s) if !negative => {
                let (prefix, rest) = match s.get(..2) {
                    Some(p @ ("d_" | "u_" | "r_" | "p_")) => (p, &s[2..]),
                    _ => ("", s.as_str()),
                };
                let id_shaped = rest.len() == 26 && rest.bytes().all(|c| c.is_ascii_uppercase() || c.is_ascii_digit());
                if id_shaped {
                    assert!(moochy_proto::Ulid::parse(rest).is_ok(), "not a valid ULID: {s}");
                    let ok = match prefix {
                        "d_" => s.parse::<moochy_proto::DeviceId>().is_ok(),
                        "u_" => s.parse::<moochy_proto::UserId>().is_ok(),
                        "r_" => s.parse::<moochy_proto::RepoId>().is_ok(),
                        "p_" => s.parse::<moochy_proto::PledgeId>().is_ok(),
                        _ => s.parse::<moochy_proto::TaskId>().is_ok(),
                    };
                    assert!(ok, "listed as valid but rejected by the parser: {s}");
                    *seen += 1;
                }
            }
            _ => {}
        }
    }
    let dir = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("../../../spec/vectors");
    let mut seen = 0;
    for e in std::fs::read_dir(dir).unwrap() {
        let p = e.unwrap().path();
        if p.extension().is_some_and(|x| x == "json") {
            walk(&serde_json::from_str(&std::fs::read_to_string(&p).unwrap()).unwrap(), false, &mut seen);
        }
    }
    assert!(seen > 20, "only {seen} ids checked");
}
