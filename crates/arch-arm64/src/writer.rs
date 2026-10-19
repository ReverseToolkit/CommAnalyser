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

    /// `B.cond` with a PC-relative byte offset.
    pub fn b_cond(&mut self, cond: u8, offset: i64) -> bool {
        if offset & 3 != 0 || !(-(1 << 20)..(1 << 20)).contains(&offset) {
            return false;
        }
        let imm19 = ((offset >> 2) as u32) & 0x7_FFFF;
        self.put(0x5400_0000 | (imm19 << 5) | (cond as u32 & 0xF));
        true
    }

    /// `CBZ` / `CBNZ`.
    pub fn cbz(&mut self, sf: bool, nonzero: bool, rt: u8, offset: i64) -> bool {
        if offset & 3 != 0 || !(-(1 << 20)..(1 << 20)).contains(&offset) {
            return false;
        }
        let imm19 = ((offset >> 2) as u32) & 0x7_FFFF;
        let op = if nonzero { 1u32 << 24 } else { 0 };
        let sf = if sf { 1u32 << 31 } else { 0 };
        self.put(0x3400_0000 | sf | op | (imm19 << 5) | (rt as u32));
        true
    }

    /// `TBZ` / `TBNZ`.
    pub fn tbz(&mut self, op: bool, rt: u8, bit: u8, offset: i64) -> bool {
        if offset & 3 != 0 || !(-(1 << 15)..(1 << 15)).contains(&offset) {
            return false;
        }
        let imm14 = ((offset >> 2) as u32) & 0x3FFF;
        let op = if op { 1u32 << 24 } else { 0 };
        let b5 = ((bit as u32) & 0x20) << 26;
        let b40 = ((bit as u32) & 0x1F) << 19;
        self.put(0x3600_0000 | b5 | op | b40 | (imm14 << 5) | (rt as u32));
        true
    }

    /// 64-bit `MOVZ`.
    pub fn movz(&mut self, rd: u8, imm16: u16, shift: u8) {
        debug_assert!(shift % 16 == 0 && shift <= 48);
        self.put(0xD280_0000 | (((shift / 16) as u32) << 21) | ((imm16 as u32) << 5) | (rd as u32));
    }

    /// 64-bit `MOVK`.
    pub fn movk(&mut self, rd: u8, imm16: u16, shift: u8) {
        debug_assert!(shift % 16 == 0 && shift <= 48);
        self.put(0xF280_0000 | (((shift / 16) as u32) << 21) | ((imm16 as u32) << 5) | (rd as u32));
    }

    /// Materialise an arbitrary 64-bit value into `rd` (4 instructions).
    pub fn abs_addr(&mut self, rd: u8, value: u64) {
        self.movz(rd, value as u16, 0);
        self.movk(rd, (value >> 16) as u16, 16);
        self.movk(rd, (value >> 32) as u16, 32);
        self.movk(rd, (value >> 48) as u16, 48);
    }

    /// 32-bit `LDR` (literal).
    pub fn ldr_literal_w(&mut self, rt: u8, offset: i64) -> bool {
        if offset & 3 != 0 || !(-(1 << 20)..(1 << 20)).contains(&offset) {
            return false;
        }
        let imm19 = ((offset >> 2) as u32) & 0x7_FFFF;
        self.put(0x1800_0000 | (imm19 << 5) | (rt as u32));
        true
    }

    /// `LDRSW` (literal).
    pub fn ldrsw_literal(&mut self, rt: u8, offset: i64) -> bool {
        if offset & 3 != 0 || !(-(1 << 20)..(1 << 20)).contains(&offset) {
            return false;
        }
        let imm19 = ((offset >> 2) as u32) & 0x7_FFFF;
        self.put(0x9800_0000 | (imm19 << 5) | (rt as u32));
        true
    }

    /// `STP Xt, Xt2, [Xn, #imm]` (signed offset form, imm multiple of 8).
    pub fn stp(&mut self, rt: u8, rt2: u8, rn: u8, offset: i64) {
        debug_assert!(offset % 8 == 0 && (-512..512).contains(&offset));
        let imm7 = ((offset / 8) as u32) & 0x7F;
        self.put(
            0xA900_0000 | (imm7 << 15) | ((rt2 as u32) << 10) | ((rn as u32) << 5) | rt as u32,
        );
    }

    /// `LDP Xt, Xt2, [Xn, #imm]`.
    pub fn ldp(&mut self, rt: u8, rt2: u8, rn: u8, offset: i64) {
        debug_assert!(offset % 8 == 0 && (-512..512).contains(&offset));
        let imm7 = ((offset / 8) as u32) & 0x7F;
        self.put(
            0xA940_0000 | (imm7 << 15) | ((rt2 as u32) << 10) | ((rn as u32) << 5) | rt as u32,
        );
    }

    /// `STR Xt, [Xn, #imm]` (unsigned offset, imm multiple of 8).
    pub fn stp_d(&mut self, rt: u8, rt2: u8, rn: u8, offset: i64) {
        let imm = (offset / 8) as u32 & 0x7F;
        let word =
            0x6D00_0000 | (imm << 15) | ((rt2 as u32) << 10) | ((rn as u32) << 5) | rt as u32;
        self.put(word);
    }

    pub fn ldp_d(&mut self, rt: u8, rt2: u8, rn: u8, offset: i64) {
        let imm = (offset / 8) as u32 & 0x7F;
        let word =
            0x6D40_0000 | (imm << 15) | ((rt2 as u32) << 10) | ((rn as u32) << 5) | rt as u32;
        self.put(word);
    }

    pub fn str_imm(&mut self, rt: u8, rn: u8, offset: u32) {
        debug_assert!(offset % 8 == 0 && offset < 32768);
        self.put(0xF900_0000 | ((offset / 8) << 10) | ((rn as u32) << 5) | rt as u32);
    }

    /// `LDR Xt, [Xn, #imm]` (unsigned offset, imm multiple of 8).
    pub fn ldr_imm(&mut self, rt: u8, rn: u8, offset: u32) {
        debug_assert!(offset % 8 == 0 && offset < 32768);
        self.put(0xF940_0000 | ((offset / 8) << 10) | ((rn as u32) << 5) | rt as u32);
    }

    /// `SUB SP, SP, #imm` (imm multiple of 16, <= 4095).
    pub fn sub_sp(&mut self, imm: u32) {
        debug_assert!(imm % 16 == 0 && imm <= 4095);
        self.put(0xD100_0000 | (imm << 10) | (31 << 5) | 31);
    }

    /// `ADD SP, SP, #imm`.
    pub fn add_sp(&mut self, imm: u32) {
        debug_assert!(imm % 16 == 0 && imm <= 4095);
        self.put(0x9100_0000 | (imm << 10) | (31 << 5) | 31);
    }

    /// `STP Xt, Xt2, [Xn, #imm]!` (pre-index).
    pub fn stp_pre(&mut self, rt: u8, rt2: u8, rn: u8, offset: i64) {
        debug_assert!(offset % 8 == 0 && (-512..512).contains(&offset));
        let imm7 = ((offset / 8) as u32) & 0x7F;
        self.put(
            0xA980_0000 | (imm7 << 15) | ((rt2 as u32) << 10) | ((rn as u32) << 5) | rt as u32,
        );
    }

    /// `LDP Xt, Xt2, [Xn], #imm` (post-index).
    pub fn ldp_post(&mut self, rt: u8, rt2: u8, rn: u8, offset: i64) {
        debug_assert!(offset % 8 == 0 && (-512..512).contains(&offset));
        let imm7 = ((offset / 8) as u32) & 0x7F;
        self.put(
            0xA8C0_0000 | (imm7 << 15) | ((rt2 as u32) << 10) | ((rn as u32) << 5) | rt as u32,
        );
    }

    /// `ADRP Xd, page`.
    pub fn adrp(&mut self, rd: u8, pc: u64, target: u64) -> bool {
        let page_pc = pc & !0xFFF;
        let page_tgt = target & !0xFFF;
        let delta = (page_tgt as i64).wrapping_sub(page_pc as i64);
        if !(-(1 << 32)..(1 << 32)).contains(&delta) {
            return false;
        }
        let imm = (delta >> 12) as u32;
        let immlo = imm & 3;
        let immhi = (imm >> 2) & 0x7_FFFF;
        self.put(0x9000_0000 | (immlo << 29) | (immhi << 5) | rd as u32);
        true
    }

    /// `ADD Xd, Xn, #imm` (12-bit, unshifted).
    pub fn add_imm(&mut self, rd: u8, rn: u8, imm: u32) {
        debug_assert!(imm < 4096);
        self.put(0x9100_0000 | (imm << 10) | ((rn as u32) << 5) | rd as u32);
    }

    /// `STR Xt, [Xn, #imm]` signed offset (unscaled) when imm is not a multiple of 8.
    pub fn str_reg_offset(&mut self, rt: u8, rn: u8, offset: i64, is_32: bool) {
        if offset >= 0 && offset % 8 == 0 && offset < 32768 && !is_32 {
            self.str_imm(rt, rn, offset as u32);
            return;
        }
        let size = if is_32 { 0xB8u32 } else { 0xF8 };
        // STUR signed 9-bit
        let imm9 = (offset as u32) & 0x1FF;
        self.put((size << 24) | (imm9 << 12) | ((rn as u32) << 5) | rt as u32);
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
