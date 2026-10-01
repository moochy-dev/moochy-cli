//! Standard base64 (RFC 4648 §4, padded), canonical decoding only: the signed-note
//! format uses it for roots, signatures and verifier keys.

const ALPHA: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

fn val(c: u8) -> Option<u32> {
    ALPHA.iter().position(|&a| a == c).and_then(|p| u32::try_from(p).ok())
}

/// Strict decode: length multiple of 4, padding only at the end, zero unused bits.
pub fn decode(s: &[u8]) -> Option<Vec<u8>> {
    if s.is_empty() {
        return Some(Vec::new());
    }
    let (quads, rest) = s.as_chunks::<4>();
    if !rest.is_empty() {
        return None;
    }
    let mut out = Vec::with_capacity(s.len());
    let last = quads.len().checked_sub(1)?;
    for (i, &[c0, c1, c2, c3]) in quads.iter().enumerate() {
        let pad = match (c2, c3) {
            (b'=', b'=') => 2,
            (_, b'=') => 1,
            _ => 0,
        };
        if pad > 0 && i != last {
            return None;
        }
        let n = (val(c0)? << 18)
            | (val(c1)? << 12)
            | (if pad == 2 { 0 } else { val(c2)? << 6 })
            | (if pad >= 1 { 0 } else { val(c3)? });
        let bytes = n.to_be_bytes();
        match pad {
            0 => out.extend_from_slice(bytes.get(1..4)?),
            1 if n.trailing_zeros() >= 8 => out.extend_from_slice(bytes.get(1..3)?),
            2 if n.trailing_zeros() >= 16 => out.extend_from_slice(bytes.get(1..2)?),
            _ => return None,
        }
    }
    Some(out)
}

#[cfg(test)]
pub fn encode(b: &[u8]) -> String {
    let mut out = String::with_capacity(b.len().saturating_mul(2));
    for c in b.chunks(3) {
        let byte = |i: usize| u32::from(c.get(i).copied().unwrap_or(0));
        let n = byte(0) << 16 | byte(1) << 8 | byte(2);
        let sym = |shift: u32| char::from(ALPHA.get(((n >> shift) & 63) as usize).copied().unwrap_or(b'='));
        out.push(sym(18));
        out.push(sym(12));
        out.push(if c.len() > 1 { sym(6) } else { '=' });
        out.push(if c.len() > 2 { sym(0) } else { '=' });
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn round_trip_and_strictness() {
        for n in 0..70u8 {
            let v: Vec<u8> = (0..n).map(|i| i.wrapping_mul(37) ^ 0xa5).collect();
            assert_eq!(decode(encode(&v).as_bytes()).unwrap(), v);
        }
        assert_eq!(encode(b"foob"), "Zm9vYg==");
        for bad in ["Zm9vYh==", "Zm9vYg=", "Zm9=Yg==", "Zm9vY===", "Zm 9", "Zm9vYg==Zm9v", "=AAA"] {
            assert!(decode(bad.as_bytes()).is_none(), "{bad}");
        }
    }
}
