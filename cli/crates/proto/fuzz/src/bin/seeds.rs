//! Writes a seed corpus (valid frames of many shapes + bombs) into the directory given as arg 1.
//! Each file = u16 LE piece size || zstd bytes.
use std::io::Write;

fn main() {
    let dir = std::env::args().nth(1).expect("corpus dir");
    std::fs::create_dir_all(&dir).unwrap();
    let alphabet = b"the quick brown fox {\"role\":\"user\"} 0123456789\n";
    let text: Vec<u8> = (0..200_000u32).map(|i| alphabet[(i.wrapping_mul(2_654_435_761) >> 7) as usize % alphabet.len()]).collect();
    let mut seeds: Vec<(String, Vec<u8>)> = Vec::new();
    for (n, data) in [("empty", Vec::new()), ("tiny", b"{}".to_vec()), ("text", text.clone()), ("zeros", vec![0u8; 300_000]), ("small", text[..300].to_vec())] {
        for lvl in [1, 3, 19] {
            seeds.push((format!("{n}-l{lvl}"), zstd::bulk::compress(&data, lvl).unwrap()));
        }
        let mut e = zstd::stream::Encoder::new(Vec::new(), 3).unwrap();
        e.include_contentsize(false).unwrap();
        e.write_all(&data).unwrap();
        seeds.push((format!("{n}-stream"), e.finish().unwrap()));
        let mut e = zstd::stream::Encoder::new(Vec::new(), 3).unwrap();
        e.include_checksum(true).unwrap();
        e.write_all(&data).unwrap();
        seeds.push((format!("{n}-checksum"), e.finish().unwrap()));
    }
    seeds.push(("bomb-fcs".into(), zstd::bulk::compress(&vec![0u8; 8 << 20], 19).unwrap()));
    let mut e = zstd::stream::Encoder::new(Vec::new(), 19).unwrap();
    e.include_contentsize(false).unwrap();
    e.write_all(&vec![b'a'; 8 << 20]).unwrap();
    seeds.push(("bomb-stream".into(), e.finish().unwrap()));
    for (name, z) in seeds {
        for piece in [1u16, 7, 4096, 65_497, 0] {
            let mut f = piece.to_le_bytes().to_vec();
            f.extend_from_slice(&z);
            std::fs::write(format!("{dir}/{name}-p{piece}"), f).unwrap();
        }
    }
}
