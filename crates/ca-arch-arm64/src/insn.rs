use crate::sign_extend;

/// The subset of AArch64 instructions needed by the inline-hook relocator.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Insn {
    Nop,
    /// `BTI c` / `BTI jc` landing pads.
    Bti,
    /// Unconditional `B`.
    B {
        offset: i64,
    },
    /// `BL`.
    Bl {
        offset: i64,
    },
    /// `B.cond`.
    BCond {
        cond: u8,
        offset: i64,
    },
    /// `CBZ` / `CBNZ`.
    Cbz {
        sf: bool,
        nonzero: bool,
        rt: u8,
        offset: i64,
    },
    /// `TBZ` / `TBNZ`.
    Tbz {
        op: bool,
        rt: u8,
        bit: u8,
        offset: i64,
    },
    /// `ADR`.
    Adr {
        rd: u8,
        offset: i64,
    },
    /// `ADRP`.
    Adrp {
        rd: u8,
        offset: i64,
    },
    /// `LDR` / `LDRSW` / `PRFM` (literal form).
    LdrLiteral {
        rt: u8,
        offset: i64,
        is_64: bool,
        is_signed: bool,
        is_prfm: bool,
    },
    /// `BR`.
    Br {
        rn: u8,
    },
    /// `BLR`.
    Blr {
        rn: u8,
    },
    /// `RET`.
    Ret {
        rn: u8,
    },
    /// Anything the relocator does not understand yet.
    Other(u32),
}

impl Insn {
    #[inline]
    pub fn is_branch(&self) -> bool {
        matches!(
            self,
            Insn::B { .. }
                | Insn::Bl { .. }
                | Insn::BCond { .. }
                | Insn::Cbz { .. }
                | Insn::Tbz { .. }
                | Insn::Br { .. }
                | Insn::Blr { .. }
                | Insn::Ret { .. }
        )
    }
}

/// Classify one 32-bit AArch64 instruction word.
pub fn classify(word: u32) -> Insn {
    // B / BL: 000101 / 100101 in bits 31..26.
    if word & 0x7C00_0000 == 0x1400_0000 {
        let imm = sign_extend((word & 0x03FF_FFFF) as u64, 26) << 2;
        return if word & 0x8000_0000 != 0 {
            Insn::Bl { offset: imm }
        } else {
            Insn::B { offset: imm }
        };
    }

    // B.cond: 01010100 imm19 0 cond.
    if word & 0xFF00_0010 == 0x5400_0000 {
        let cond = (word & 0xF) as u8;
        let imm = sign_extend(((word >> 5) & 0x7_FFFF) as u64, 19) << 2;
        return Insn::BCond { cond, offset: imm };
    }

    // CBZ / CBNZ: sf 011010 op imm19 Rt.
    if word & 0x7E00_0000 == 0x3400_0000 {
        let sf = word & 0x8000_0000 != 0;
        let nonzero = word & 0x0100_0000 != 0;
        let rt = (word & 0x1F) as u8;
        let imm = sign_extend(((word >> 5) & 0x7_FFFF) as u64, 19) << 2;
        return Insn::Cbz {
            sf,
            nonzero,
            rt,
            offset: imm,
        };
    }

    // TBZ / TBNZ: b5 011011 op b40 imm14 Rt.
    if word & 0x7E00_0000 == 0x3600_0000 {
        let op = word & 0x0100_0000 != 0;
        let b5 = ((word >> 31) & 1) as u8;
        let b40 = ((word >> 19) & 0x1F) as u8;
        let rt = (word & 0x1F) as u8;
        let imm = sign_extend(((word >> 5) & 0x3FFF) as u64, 14) << 2;
        return Insn::Tbz {
            op,
            rt,
            bit: (b5 << 5) | b40,
            offset: imm,
        };
    }

    // ADR / ADRP: op 10000 immlo 1 immhi Rd.
    if word & 0x1F00_0000 == 0x1000_0000 {
        let rd = (word & 0x1F) as u8;
        let immlo = ((word >> 29) & 0x3) as u64;
        let immhi = ((word >> 5) & 0x7_FFFF) as u64;
        let imm = sign_extend((immhi << 2) | immlo, 21);
        return if word & 0x8000_0000 != 0 {
            Insn::Adrp {
                rd,
                offset: imm << 12,
            }
        } else {
            Insn::Adr { rd, offset: imm }
        };
    }

    // Load register (literal): opc 011000 imm19 Rt.
    if word & 0x3B00_0000 == 0x1800_0000 {
        let opc = (word >> 30) & 0x3;
        let rt = (word & 0x1F) as u8;
        let imm = sign_extend(((word >> 5) & 0x7_FFFF) as u64, 19) << 2;
        let (is_64, is_signed, is_prfm) = match opc {
            0b00 => (false, false, false),
            0b01 => (true, false, false),
            0b10 => (false, true, false),
            0b11 => (false, false, true),
            _ => unreachable!(),
        };
        return Insn::LdrLiteral {
            rt,
            offset: imm,
            is_64,
            is_signed,
            is_prfm,
        };
    }

    // BR / BLR / RET: 1101011 op 11111 000000 Rn 00000.
    if word & 0xFFFF_FC1F == 0xD61F_0000 {
        return Insn::Br {
            rn: ((word >> 5) & 0x1F) as u8,
        };
    }
    if word & 0xFFFF_FC1F == 0xD63F_0000 {
        return Insn::Blr {
            rn: ((word >> 5) & 0x1F) as u8,
        };
    }
    if word & 0xFFFF_FC1F == 0xD65F_0000 {
        return Insn::Ret {
            rn: ((word >> 5) & 0x1F) as u8,
        };
    }

    if word == 0xD503_201F {
        return Insn::Nop;
    }
    if word == 0xD503_245F || word == 0xD503_24DF {
        return Insn::Bti;
    }

    Insn::Other(word)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn branches() {
        assert_eq!(classify(0x1400_0000), Insn::B { offset: 0 });
        assert_eq!(classify(0x17FF_FFFF), Insn::B { offset: -4 });
        assert_eq!(classify(0x9400_0000), Insn::Bl { offset: 0 });
        assert_eq!(classify(0x97FF_FFFF), Insn::Bl { offset: -4 });
    }

    #[test]
    fn conditional() {
        assert_eq!(classify(0x5400_0000), Insn::BCond { cond: 0, offset: 0 });
        assert_eq!(classify(0x5400_0001), Insn::BCond { cond: 1, offset: 0 });
        assert_eq!(
            classify(0x34FF_FFFF),
            Insn::Cbz {
                sf: false,
                nonzero: false,
                rt: 31,
                offset: -4
            }
        );
        assert_eq!(
            classify(0x3600_0000),
            Insn::Tbz {
                op: false,
                rt: 0,
                bit: 0,
                offset: 0
            }
        );
    }

    #[test]
    fn pc_relative() {
        assert_eq!(classify(0x1000_0000), Insn::Adr { rd: 0, offset: 0 });
        assert_eq!(classify(0x9000_0000), Insn::Adrp { rd: 0, offset: 0 });
        assert_eq!(
            classify(0x5800_0000),
            Insn::LdrLiteral {
                rt: 0,
                offset: 0,
                is_64: true,
                is_signed: false,
                is_prfm: false
            }
        );
        assert_eq!(
            classify(0x9800_0000),
            Insn::LdrLiteral {
                rt: 0,
                offset: 0,
                is_64: false,
                is_signed: true,
                is_prfm: false
            }
        );
    }

    #[test]
    fn indirect() {
        assert_eq!(classify(0xD61F_0000), Insn::Br { rn: 0 });
        assert_eq!(classify(0xD63F_0000), Insn::Blr { rn: 0 });
        assert_eq!(classify(0xD65F_03C0), Insn::Ret { rn: 30 });
        assert_eq!(classify(0xD503_201F), Insn::Nop);
        assert_eq!(classify(0xD503_245F), Insn::Bti);
    }
}
