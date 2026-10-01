//! Tiny big-endian binary codec shared by the store log and the isolation protocol.
//! Readers are bounds-checked and never allocate.

pub(crate) struct W<'a>(pub &'a mut Vec<u8>);

impl W<'_> {
    pub fn u8(&mut self, v: u8) {
        self.0.push(v);
    }
    pub fn u32(&mut self, v: u32) {
        self.0.extend_from_slice(&v.to_be_bytes());
    }
    pub fn u64(&mut self, v: u64) {
        self.0.extend_from_slice(&v.to_be_bytes());
    }
    /// `u32_be len || bytes` (callers bound lengths far below 4 GiB).
    pub fn bytes(&mut self, b: &[u8]) {
        self.u32(u32::try_from(b.len()).unwrap_or(u32::MAX));
        self.0.extend_from_slice(b);
    }
}

pub(crate) struct Rd<'a>(pub &'a [u8]);

impl<'a> Rd<'a> {
    pub fn take(&mut self, n: usize) -> Option<&'a [u8]> {
        if n > self.0.len() {
            return None;
        }
        let (a, b) = self.0.split_at(n);
        self.0 = b;
        Some(a)
    }
    pub fn u8(&mut self) -> Option<u8> {
        self.take(1)?.first().copied()
    }
    pub fn u32(&mut self) -> Option<u32> {
        Some(u32::from_be_bytes(self.take(4)?.try_into().ok()?))
    }
    pub fn u64(&mut self) -> Option<u64> {
        Some(u64::from_be_bytes(self.take(8)?.try_into().ok()?))
    }
    pub fn bytes(&mut self) -> Option<&'a [u8]> {
        let n = self.u32()?;
        self.take(usize::try_from(n).ok()?)
    }
    pub fn is_empty(&self) -> bool {
        self.0.is_empty()
    }
}
