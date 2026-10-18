/// Small AArch64 code writer with the encodings needed by the hook engine.
#[derive(Default, Clone)]
pub struct CodeWriter {
    bytes: Vec<u8>,
}

impl CodeWriter {
    pub fn new() -> Self {
        Self { bytes: Vec::new() }
    }

    pub fn with_capacity(capacity: usize) -> Self {
        Self {
            bytes: Vec::with_capacity(capacity),
        }
    }

    #[inline]
    pub fn len(&self) -> usize {
        self.bytes.len()
    }

    #[inline]
    pub fn is_empty(&self) -> bool {
        self.bytes.is_empty()
    }

    #[inline]
    pub fn clear(&mut self) {
        self.bytes.clear();
    }

    #[inline]
    pub fn bytes(&self) -> &[u8] {
        &self.bytes
    }

    #[inline]
    pub fn into_bytes(self) -> Vec<u8> {
        self.bytes
    }

    #[inline]
    pub fn put(&mut self, word: u32) {
        self.bytes.extend_from_slice(&word.to_le_bytes());
    }

    #[inline]
    pub fn put_bytes(&mut self, bytes: &[u8]) {
        self.bytes.extend_from_slice(bytes);
    }

    #[inline]
    pub fn put_u64(&mut self, value: u64) {
        self.bytes.extend_from_slice(&value.to_le_bytes());
    }

    /// Pad with NOPs to a 4-byte boundary (and optionally further).
    pub fn align(&mut self, alignment: usize) {
        debug_assert!(alignment.is_power_of_two());
        while self.bytes.len() % alignment != 0 {
            self.put(0xD503_201F); // NOP
        }
    }

    pub fn nop(&mut self) {
        self.put(0xD503_201F);
    }

    pub fn bti_c(&mut self) {
        self.put(0xD503_245F);
    }

    pub fn bti_jc(&mut self) {
        self.put(0xD503_24DF);
    }

    pub fn ret(&mut self, rn: u8) {
        self.put(0xD65F_0000 | ((rn as u32) << 5));
    }

    pub fn br(&mut self, rn: u8) {
        self.put(0xD61F_0000 | ((rn as u32) << 5));
    }

    pub fn blr(&mut self, rn: u8) {
        self.put(0xD63F_0000 | ((rn as u32) << 5));
    }

    pub fn b_imm(&mut self, offset: i64) -> bool {
        if offset & 3 != 0 || !(-(1 << 27)..(1 << 27)).contains(&offset) {
            return false;
        }
        let imm26 = ((offset >> 2) as u32) & 0x03FF_FFFF;
        self.put(0x1400_0000 | imm26);
        true
    }

    pub fn bl_imm(&mut self, offset: i64) -> bool {
        if offset & 3 != 0 || !(-(1 << 27)..(1 << 27)).contains(&offset) {
            return false;
        }
        let imm26 = ((offset >> 2) as u32) & 0x03FF_FFFF;
        self.put(0x9400_0000 | imm26);
        true
    }

    /// `LDR Xt, #imm` (64-bit literal load, PC-relative).
    pub fn ldr_literal_x(&mut self, rt: u8, offset: i64) -> bool {
        if offset & 3 != 0 || !(-(1 << 20)..(1 << 20)).contains(&offset) {
            return false;
        }
        let imm19 = ((offset >> 2) as u32) & 0x7_FFFF;
        self.put(0x5800_0000 | (imm19 << 5) | (rt as u32));
        true
    }

    /// Absolute unconditional branch: `ldr x16, #8; br x16; .quad target`.
    pub fn abs_b(&mut self, target: usize) {
        self.ldr_literal_x(16, 8);
        self.br(16);
        self.put_u64(target as u64);
    }

    /// Absolute call preserving LR.
    ///
    /// Layout (24 bytes):
    ///   ldr x16, #16
    ///   blr x16
    ///   b   #16
    ///   nop
    ///   .quad target
    pub fn abs_bl(&mut self, target: usize) {
        self.ldr_literal_x(16, 16);
        self.blr(16);
        // Branch over the literal.  At offset 8, +16 lands after the quad.
        self.b_imm(16);
        self.nop();
        self.put_u64(target as u64);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn words(bytes: &[u8]) -> Vec<u32> {
        bytes
            .chunks_exact(4)
            .map(|c| u32::from_le_bytes(c.try_into().unwrap()))
            .collect()
    }

    #[test]
    fn simple_encodings() {
        let mut w = CodeWriter::new();
        w.nop();
        w.ret(30);
        w.br(16);
        w.blr(17);
        assert_eq!(
            words(w.bytes()),
            vec![0xD503_201F, 0xD65F_03C0, 0xD61F_0200, 0xD63F_0220]
        );
    }

    #[test]
    fn abs_branch_layout() {
        let mut w = CodeWriter::new();
        w.abs_b(0x1234_5678);
        let b = w.bytes();
        assert_eq!(b.len(), 16);
        let wds = words(b);
        assert_eq!(wds[0], 0x5800_0050); // ldr x16, #8
        assert_eq!(wds[1], 0xD61F_0200); // br x16
        assert_eq!(
            u64::from_le_bytes(b[8..16].try_into().unwrap()),
            0x1234_5678
        );
    }

    #[test]
    fn abs_call_layout() {
        let mut w = CodeWriter::new();
        w.abs_bl(0xDEAD_BEEF);
        let b = w.bytes();
        assert_eq!(b.len(), 24);
        let wds = words(b);
        assert_eq!(wds[0], 0x5800_0090); // ldr x16, #16
        assert_eq!(wds[1], 0xD63F_0200); // blr x16
        assert_eq!(wds[2], 0x1400_0004); // b #16
        assert_eq!(wds[3], 0xD503_201F); // nop
        assert_eq!(
            u64::from_le_bytes(b[16..24].try_into().unwrap()),
            0xDEAD_BEEF
        );
    }
}
