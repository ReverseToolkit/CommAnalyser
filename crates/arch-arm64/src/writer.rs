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

    /// Overwrite one instruction that was already emitted at byte `at`.
    ///
    /// Returns `false` when `at` does not address a whole instruction; the
    /// caller decides whether that is a label bug or an expected gap.  This is
    /// a public encoder entry point, so it must not panic on a bad offset.
    #[must_use]
    pub fn set_word(&mut self, at: usize, word: u32) -> bool {
        let Some(slot) = self.bytes.get_mut(at..at + 4) else {
            return false;
        };
        slot.copy_from_slice(&word.to_le_bytes());
        true
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

    /// `XPACI Xd` — strip IA PAC (`gum_arm64_writer_put_xpaci_reg`).
    pub fn xpaci(&mut self, rd: u8) {
        self.put(0xDAC1_43E0 | rd as u32);
    }

    /// `PACIZA Xd` — sign IA, modifier 0 (`gum_sign_code_pointer`).
    pub fn paciza(&mut self, rd: u8) {
        self.put(0xDAC1_23E0 | rd as u32);
    }

    /// `BRAAZ Xn` — gum `put_br_reg` with ptrauth extra `0x81f`.
    pub fn braaz(&mut self, rn: u8) {
        self.put(0xD61F_0000 | ((rn as u32) << 5) | 0x81F);
    }

    /// Frida `put_jmp_reg` for a raw address: `RET Xn`.
    ///
    /// BTI-exempt, and it does not authenticate against SP. Use this for a
    /// computed resume (`patch + 4`). A PAC-signed LR needs [`jmp_auth_lr`].
    pub fn jmp_signed(&mut self, rn: u8) {
        self.ret(rn);
    }

    /// Frida leave: `gum_sign_code_pointer` then `BRAAZ`.
    ///
    /// `RET` of an SP-PAC'd LR fetches the signed bits and MAPERRs. Strip,
    /// re-sign with modifier 0, then branch.
    pub fn jmp_auth_lr(&mut self, rn: u8) {
        self.xpaci(rn);
        self.paciza(rn);
        self.braaz(rn);
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

    /// `STP Qt, Qt2, [Xn, #imm]` (128-bit SIMD, imm multiple of 16).
    pub fn stp_q(&mut self, rt: u8, rt2: u8, rn: u8, offset: i64) {
        debug_assert!(offset % 16 == 0 && (-1024..1024).contains(&offset));
        let imm7 = ((offset / 16) as u32) & 0x7F;
        self.put(
            0xAD00_0000 | (imm7 << 15) | ((rt2 as u32) << 10) | ((rn as u32) << 5) | rt as u32,
        );
    }

    /// `LDP Qt, Qt2, [Xn, #imm]`.
    pub fn ldp_q(&mut self, rt: u8, rt2: u8, rn: u8, offset: i64) {
        debug_assert!(offset % 16 == 0 && (-1024..1024).contains(&offset));
        let imm7 = ((offset / 16) as u32) & 0x7F;
        self.put(
            0xAD40_0000 | (imm7 << 15) | ((rt2 as u32) << 10) | ((rn as u32) << 5) | rt as u32,
        );
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
    /// Move `sources[i]` into `x{i}`, in parallel.
    ///
    /// Argument setup cannot be emitted in source order: with `[x1, x0]` a
    /// naive `mov x0, x1; mov x1, x0` copies the new x0 into x1.  This
    /// schedules the moves like a parallel assignment: a move is emitted only
    /// once its destination is no longer a source for any pending move, and a
    /// cycle is broken by saving one destination in x16.
    ///
    /// `None` leaves that destination untouched.  Returns `false` when the
    /// set cannot be scheduled (more than 8 arguments, an invalid register, or
    /// a cycle that would need a second scratch register).
    ///
    /// # Examples
    ///
    /// ```
    /// use arch_arm64::CodeWriter;
    ///
    /// // x0 and x1 swap in parallel: one save through x16 plus two moves,
    /// // never an overwrite of a value that is still needed.
    /// let mut writer = CodeWriter::new();
    /// assert!(writer.move_arg_registers(&[Some(1), Some(0)]));
    /// assert_eq!(writer.bytes().len(), 12);
    ///
    /// // A destination that is already correct needs no instruction.
    /// let mut writer = CodeWriter::new();
    /// assert!(writer.move_arg_registers(&[Some(0), None]));
    /// assert!(writer.bytes().is_empty());
    /// ```
    pub fn move_arg_registers(&mut self, sources: &[Option<u8>]) -> bool {
        if sources.len() > 8 {
            return false;
        }
        if sources.iter().flatten().any(|&source| source > 31) {
            return false;
        }
        let mut pending: Vec<Option<u8>> = sources.to_vec();
        for (index, source) in pending.iter_mut().enumerate() {
            // x31 in a source means SP; anything else is a plain register.
            if *source == Some(index as u8) {
                *source = None;
            }
        }
        loop {
            if pending.iter().all(Option::is_none) {
                return true;
            }
            // A move whose destination is not read by any pending move.
            let free = (0..pending.len()).find(|&index| {
                pending[index].is_some()
                    && !pending
                        .iter()
                        .any(|source| *source == Some(index as u8))
            });
            if let Some(index) = free {
                let source = pending[index].take().expect("checked above");
                self.mov_register(index as u8, source);
                continue;
            }
            // Every remaining move is part of a cycle.  x16 is free because
            // destinations are x0..x7, but only one save may be outstanding.
            if pending.iter().any(|source| *source == Some(16)) {
                return false;
            }
            let Some(pivot) = pending.iter().position(Option::is_some) else {
                return true;
            };
            self.mov_register(16, pivot as u8);
            for source in pending.iter_mut() {
                if *source == Some(pivot as u8) {
                    *source = Some(16);
                }
            }
        }
    }

    /// `mov xd, xm` (or `add xd, sp, #0` when the source is x31/SP).
    fn mov_register(&mut self, destination: u8, source: u8) {
        if source == 31 {
            // ORR with Rm = 31 reads XZR, not SP; ADD encodes SP as Rn = 31.
            self.put(0x9100_03E0 | destination as u32);
        } else {
            self.put(0xAA00_03E0 | ((source as u32) << 16) | destination as u32);
        }
    }

    /// Store at a signed byte offset, choosing STR (scaled) or STUR.
    ///
    /// Unaligned offsets are legal up to the STUR range and are encoded
    /// unscaled, so they are never rounded. Offsets outside both encodings
    /// use a scratch register: add/sub with an immediate when possible,
    /// otherwise the offset is materialized with movz/movk and added.
    ///
    /// # Side effect
    ///
    /// The scratch fallback clobbers **x16**, or **x17** when rt or rn is
    /// x16. It is only taken for offsets that neither STR nor STUR can
    /// express; small and aligned offsets emit a single instruction and leave
    /// every other register alone. When both x16 and x17 are operands there
    /// is no scratch available and the call returns false without emitting
    /// anything.
    ///
    /// # Examples
    ///
    /// ```
    /// use arch_arm64::CodeWriter;
    ///
    /// // Aligned and small: one instruction, no scratch register.
    /// let mut writer = CodeWriter::new();
    /// assert!(writer.str_reg_offset(0, 1, 8, false));
    /// assert_eq!(writer.bytes().len(), 4);
    ///
    /// // Unaligned but inside the STUR window: still one instruction.
    /// let mut writer = CodeWriter::new();
    /// assert!(writer.str_reg_offset(0, 1, 5, false));
    /// assert_eq!(writer.bytes().len(), 4);
    ///
    /// // Large: materialized through x16.
    /// let mut writer = CodeWriter::new();
    /// assert!(writer.str_reg_offset(0, 1, -1000, false));
    /// assert!(writer.bytes().len() > 4);
    ///
    /// // Both scratch candidates are operands: refused, nothing emitted.
    /// let mut writer = CodeWriter::new();
    /// assert!(!writer.str_reg_offset(16, 17, 5001, false));
    /// assert!(writer.bytes().is_empty());
    /// ```
    #[must_use]
    pub fn str_reg_offset(&mut self, rt: u8, rn: u8, offset: i64, is_32: bool) -> bool {
        if rt > 31 || rn > 31 {
            return false;
        }
        // Scaled form: the scale is the access size (8 or 4 bytes).
        let (scale, limit) = if is_32 { (4, 16384) } else { (8, 32768) };
        if offset >= 0 && offset % scale == 0 && offset < limit {
            if is_32 {
                self.str_imm_32(rt, rn, offset as u32);
            } else {
                self.str_imm(rt, rn, offset as u32);
            }
            return true;
        }
        // Unscaled form covers the signed 9-bit window at any alignment.
        if (-256..=255).contains(&offset) {
            let size = if is_32 { 0xB8u32 } else { 0xF8 };
            let imm9 = (offset as u32) & 0x1FF;
            self.put((size << 24) | (imm9 << 12) | ((rn as u32) << 5) | rt as u32);
            return true;
        }
        // Large offset: compute the address in a scratch register, then store
        // at offset 0.  x16/x17 are the only registers this may clobber; if
        // both are in use by the operands the request is refused.
        let scratch = if rt != 16 && rn != 16 {
            16
        } else if rt != 17 && rn != 17 {
            17
        } else {
            return false;
        };
        if !self.add_immediate(scratch, rn, offset) {
            // Offset does not fit ADD's 12-bit immediate: materialize it.
            self.abs_addr(scratch, offset as u64);
            // add scratch, rn, scratch
            self.put(
                0x8B00_0000 | ((scratch as u32) << 16) | ((rn as u32) << 5) | scratch as u32,
            );
        }
        self.str_zero(rt, scratch, is_32);
        true
    }

    /// `add dst, base, #offset` (or `sub` for negatives), including the
    /// LSL #12 form.  Returns false when the value needs materialization.
    fn add_immediate(&mut self, dst: u8, base: u8, offset: i64) -> bool {
        let encode = |imm: u32, shift: bool, subtract: bool| -> u32 {
            let base_op = match (subtract, shift) {
                (false, false) => 0x9100_0000,
                (false, true) => 0x9140_0000,
                (true, false) => 0xD100_0000,
                (true, true) => 0xD140_0000,
            };
            base_op
                | (imm << 10)
                | ((base as u32) << 5)
                | dst as u32
        };
        if (0..=4095).contains(&offset) {
            self.put(encode(offset as u32, false, false));
            return true;
        }
        if offset > 0 && offset % 4096 == 0 && offset / 4096 <= 4095 {
            self.put(encode((offset / 4096) as u32, true, false));
            return true;
        }
        if (-4095..=0).contains(&offset) {
            self.put(encode((-offset) as u32, false, true));
            return true;
        }
        if offset < 0 && offset % 4096 == 0 && -offset / 4096 <= 4095 {
            self.put(encode((-offset / 4096) as u32, true, true));
            return true;
        }
        false
    }

    /// `str rt, [base, #0]` in the requested width.
    fn str_zero(&mut self, rt: u8, base: u8, is_32: bool) {
        let opcode = if is_32 { 0xB900_0000 } else { 0xF900_0000 };
        self.put(opcode | ((base as u32) << 5) | rt as u32);
    }

    /// `STR Wt, [Xn, #imm]` (unsigned offset, imm multiple of 4).
    pub fn str_imm_32(&mut self, rt: u8, rn: u8, offset: u32) {
        debug_assert!(offset % 4 == 0 && offset < 16384);
        self.put(0xB900_0000 | ((offset / 4) << 10) | ((rn as u32) << 5) | rt as u32);
    }

    /// Absolute unconditional branch: `ldr x16, #8; br x16; .quad target`.
    pub fn abs_b(&mut self, target: usize) {
        self.ldr_literal_x(16, 8);
        self.br(16);
        self.put_u64(target as u64);
    }

    /// Absolute resume: `ldr x16, #8; ret x16; .quad target`.
    pub fn abs_b_signed(&mut self, target: usize) {
        self.ldr_literal_x(16, 8);
        self.jmp_signed(16);
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
    fn simd_q_pair_encodings() {
        let mut w = CodeWriter::new();
        w.stp_q(0, 1, 31, 272);
        w.ldp_q(2, 3, 31, 304);
        assert_eq!(words(w.bytes()), vec![0xAD08_87E0, 0xAD49_8FE2]);
    }

    #[test]
    fn ptrauth_jmp_encodings() {
        let mut w = CodeWriter::new();
        w.xpaci(16);
        w.paciza(16);
        w.braaz(16);
        assert_eq!(
            words(w.bytes()),
            vec![0xDAC1_43F0, 0xDAC1_23F0, 0xD61F_0A1F]
        );
    }

    #[test]
    fn auth_lr_is_xpaci_paciza_braaz() {
        let mut w = CodeWriter::new();
        w.jmp_auth_lr(16);
        let words: Vec<u32> = w
            .bytes()
            .chunks_exact(4)
            .map(|c| u32::from_le_bytes(c.try_into().unwrap()))
            .collect();
        assert_eq!(words, vec![0xDAC1_43F0, 0xDAC1_23F0, 0xD61F_0A1F]);
    }

    #[test]
    fn abs_resume_is_ldr_then_ret() {
        let mut w = CodeWriter::new();
        w.abs_b_signed(0x2000);
        let words: Vec<u32> = w
            .bytes()
            .chunks_exact(4)
            .map(|c| u32::from_le_bytes(c.try_into().unwrap()))
            .collect();
        assert_eq!(words[0], 0x5800_0050); // ldr x16, #8
        assert_eq!(words[1], 0xD65F_0200); // ret x16
        assert_eq!(
            u64::from_le_bytes(w.bytes()[8..16].try_into().unwrap()),
            0x2000
        );
        assert!(!words.contains(&0xD61F_0A1F));
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

    /// Apply emitted moves to a register file and return the low destinations.
    fn simulate_moves(sources: &[Option<u8>]) -> Vec<u64> {
        let mut writer = CodeWriter::new();
        assert!(
            writer.move_arg_registers(sources),
            "scheduler rejected {sources:?}"
        );
        let mut registers: [u64; 32] = core::array::from_fn(|index| 0x1000 + index as u64);
        let stack_pointer = 0x5000u64;
        for word in words(writer.bytes()) {
            if word & 0xFFE0_FFE0 == 0xAA00_03E0 {
                // ORR Xd, XZR, Xm  ==  mov xd, xm
                let source = ((word >> 16) & 0x1F) as usize;
                let destination = (word & 0x1F) as usize;
                registers[destination] = registers[source];
            } else if word & 0xFFC0_0000 == 0x9100_0000 {
                // ADD Xd, Xn|SP, #imm
                let destination = (word & 0x1F) as usize;
                let base = ((word >> 5) & 0x1F) as usize;
                let immediate = ((word >> 10) & 0xFFF) as u64;
                registers[destination] =
                    if base == 31 { stack_pointer } else { registers[base] } + immediate;
            } else {
                panic!("unexpected move encoding {word:#08x}");
            }
        }
        registers[..sources.len()].to_vec()
    }

    fn permutations(values: &mut [u8], length: usize, visit: &mut impl FnMut(&[u8])) {
        if length <= 1 {
            visit(values);
            return;
        }
        for index in 0..length {
            permutations(values, length - 1, visit);
            if length % 2 == 0 {
                values.swap(index, length - 1);
            } else {
                values.swap(0, length - 1);
            }
        }
    }

    #[test]
    fn argument_moves_are_parallel_for_every_permutation() {
        let mut order: Vec<u8> = (0..8).collect();
        let original: [u64; 32] = core::array::from_fn(|index| 0x1000 + index as u64);
        let mut seen = 0u32;
        permutations(&mut order, 8, &mut |permutation| {
            let sources: Vec<Option<u8>> = permutation.iter().copied().map(Some).collect();
            let moved = simulate_moves(&sources);
            for (destination, &source) in permutation.iter().enumerate() {
                assert_eq!(
                    moved[destination], original[source as usize],
                    "permutation {permutation:?}: x{destination} should hold x{source}"
                );
            }
            seen += 1;
        });
        assert_eq!(seen, 40_320);
    }

    #[test]
    fn argument_moves_skip_none_and_reject_too_many() {
        let moved = simulate_moves(&[Some(3), None, Some(0)]);
        assert_eq!(moved, vec![0x1003, 0x1001, 0x1000]);

        let mut writer = CodeWriter::new();
        assert!(!writer.move_arg_registers(&[None; 9]), "8 arguments is the ABI limit");
        assert!(!writer.move_arg_registers(&[Some(32)]), "invalid register");
        assert!(writer.bytes().is_empty(), "a rejected plan emits nothing");
    }

    #[test]
    fn argument_moves_support_sp_as_a_source() {
        let moved = simulate_moves(&[Some(31)]);
        assert_eq!(moved, vec![0x5000]);
    }

    /// Decode a single store instruction into (effective offset, is_32).
    fn decode_store(bytes: &[u8]) -> (i64, bool) {
        assert_eq!(bytes.len(), 4, "expected exactly one instruction");
        let word = words(bytes)[0];
        if word & 0xFFC0_0000 == 0xF900_0000 {
            // STR Xt, [Xn, #imm12 * 8]
            ((((word >> 10) & 0xFFF) * 8) as i64, false)
        } else if word & 0xFFC0_0000 == 0xB900_0000 {
            // STR Wt, [Xn, #imm12 * 4]
            ((((word >> 10) & 0xFFF) * 4) as i64, true)
        } else if word & 0xFFE0_0C00 == 0xF800_0000 {
            // STUR Xt, [Xn, #imm9]
            let imm9 = ((word >> 12) & 0x1FF) as i64;
            ((imm9 << 55) >> 55, false)
        } else if word & 0xFFE0_0C00 == 0xB800_0000 {
            // STUR Wt, [Xn, #imm9]
            let imm9 = ((word >> 12) & 0x1FF) as i64;
            ((imm9 << 55) >> 55, true)
        } else {
            panic!("unexpected store encoding {word:#010x}");
        }
    }

    /// Replay a store sequence and return (effective address, registers).
    fn simulate_store(bytes: &[u8], rt: u8, rn: u8, is_32: bool) -> (i64, [u64; 32]) {
        let _ = (rt, rn, is_32);
        let mut regs: [u64; 32] = core::array::from_fn(|index| 0x1000 + index as u64);
        let mut address = None;
        for word in words(bytes) {
            let rd = (word & 0x1F) as usize;
            let base = ((word >> 5) & 0x1F) as usize;
            let rm = ((word >> 16) & 0x1F) as usize;
            if word & 0xFFE0_FFE0 == 0xAA00_03E0 {
                regs[rd] = if rm == 31 { 0 } else { regs[rm] };
            } else if word & 0xFF80_0000 == 0xD280_0000 {
                let immediate = ((word >> 5) & 0xFFFF) as u64;
                let shift = ((word >> 21) & 0x3) * 16;
                regs[rd] = immediate << shift;
            } else if word & 0xFF80_0000 == 0xF280_0000 {
                let immediate = ((word >> 5) & 0xFFFF) as u64;
                let shift = ((word >> 21) & 0x3) * 16;
                let mask = !(0xFFFFu64 << shift);
                regs[rd] = (regs[rd] & mask) | (immediate << shift);
            } else if word & 0xFFC0_0000 == 0x9100_0000
                || word & 0xFFC0_0000 == 0x9140_0000
            {
                let immediate = ((word >> 10) & 0xFFF) as u64;
                let shift = if word & 0x0040_0000 != 0 { 12 } else { 0 };
                regs[rd] = (if base == 31 { 0x7000 } else { regs[base] })
                    .wrapping_add(immediate << shift);
            } else if word & 0xFFC0_0000 == 0xD100_0000
                || word & 0xFFC0_0000 == 0xD140_0000
            {
                let immediate = ((word >> 10) & 0xFFF) as u64;
                let shift = if word & 0x0040_0000 != 0 { 12 } else { 0 };
                regs[rd] = (if base == 31 { 0x7000 } else { regs[base] })
                    .wrapping_sub(immediate << shift);
            } else if word & 0xFFE0_FC00 == 0x8B00_0000 {
                regs[rd] = regs[base].wrapping_add(regs[rm]);
            } else if word & 0xFFC0_0000 == 0xF900_0000 {
                address = Some((regs[base] as i64).wrapping_add(((word >> 10) & 0xFFF) as i64 * 8));
                break;
            } else if word & 0xFFC0_0000 == 0xB900_0000 {
                address = Some((regs[base] as i64).wrapping_add(((word >> 10) & 0xFFF) as i64 * 4));
                break;
            } else if word & 0xFFE0_0C00 == 0xF800_0000 {
                let imm9 = (((word >> 12) & 0x1FF) as i64) << 55 >> 55;
                address = Some(regs[base] as i64 + imm9);
                break;
            } else if word & 0xFFE0_0C00 == 0xB800_0000 {
                let imm9 = (((word >> 12) & 0x1FF) as i64) << 55 >> 55;
                address = Some(regs[base] as i64 + imm9);
                break;
            } else {
                panic!("unexpected instruction {word:#010x}");
            }
        }
        (address.expect("sequence must store once"), regs)
    }

    /// Base register of the final store, which reveals the scratch choice.
    fn store_base_register(bytes: &[u8]) -> u8 {
        for word in words(bytes) {
            let is_store = word & 0xFFC0_0000 == 0xF900_0000
                || word & 0xFFC0_0000 == 0xB900_0000
                || word & 0xFFE0_0C00 == 0xF800_0000
                || word & 0xFFE0_0C00 == 0xB800_0000;
            if is_store {
                return ((word >> 5) & 0x1F) as u8;
            }
        }
        panic!("no store in sequence");
    }

    #[test]
    fn scratch_fallback_uses_x16_then_x17() {
        // Documented side effect: the fallback clobbers x16...
        let mut writer = CodeWriter::new();
        assert!(writer.str_reg_offset(0, 1, -1000, false));
        assert_eq!(store_base_register(writer.bytes()), 16);

        // ...or x17 when an operand already owns x16.
        let mut writer = CodeWriter::new();
        assert!(writer.str_reg_offset(16, 1, 5001, false));
        assert_eq!(store_base_register(writer.bytes()), 17);

        // Direct encodings never touch a scratch register.
        let mut writer = CodeWriter::new();
        assert!(writer.str_reg_offset(0, 1, 8, false));
        assert_eq!(store_base_register(writer.bytes()), 1);
    }

    #[test]
    fn store_offsets_are_encoded_exactly_or_refused() {
        // Every one of these must reach the requested address, whether it
        // uses a scaled STR, an unscaled STUR, or the scratch fallback.
        let offsets: &[i64] = &[
            0, 8, 255, 256, 5, -3, -8, -256, // direct encodings
            257, 32761, -257, -1000,         // fallback
            4096, -4096, 5000, -5000, 32768, // ADD/SUB with LSL #12 or materialized
            1 << 20, -(1 << 20), 12345678,   // materialized
        ];
        for &offset in offsets {
            for is_32 in [false, true] {
                let mut writer = CodeWriter::new();
                assert!(
                    writer.str_reg_offset(0, 1, offset, is_32),
                    "offset {offset} (32-bit: {is_32}) should be encodable"
                );
                let (address, registers) = simulate_store(writer.bytes(), 0, 1, is_32);
                assert_eq!(
                    address,
                    0x1001 + offset,
                    "offset {offset} (32-bit: {is_32}) landed at the wrong address"
                );
                assert_eq!(registers[0], 0x1000, "rt must not be clobbered");
                assert_eq!(registers[1], 0x1001, "rn must not be clobbered");
            }
        }

        // Shortest possible sequences are still chosen.
        let mut writer = CodeWriter::new();
        assert!(writer.str_reg_offset(0, 1, 8, false));
        assert_eq!(writer.bytes().len(), 4, "aligned offset needs one instruction");
        let mut writer = CodeWriter::new();
        assert!(writer.str_reg_offset(0, 1, 32768, false));
        assert_eq!(writer.bytes().len(), 8, "ADD lsl #12 plus store");

        // With x16 and x17 both occupied there is no scratch register.
        let mut writer = CodeWriter::new();
        assert!(!writer.str_reg_offset(16, 17, 5001, false));
        assert!(writer.bytes().is_empty(), "a refused store emits nothing");
        // The same operands still work when the offset needs no scratch.
        let mut writer = CodeWriter::new();
        assert!(writer.str_reg_offset(16, 17, 8, false));
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
