use crate::insn::{classify, Insn};
use crate::writer::CodeWriter;

/// Result of relocating one instruction.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Relocated {
    /// Encoded replacement bytes.
    pub bytes: Vec<u8>,
    /// Number of source bytes consumed (4 for fixed-width AArch64).
    pub consumed: usize,
}

#[derive(Clone, Debug, PartialEq, Eq, thiserror::Error)]
pub enum RelocError {
    #[error("unsupported instruction {0:#010x}")]
    Unsupported(u32),
    #[error("branch target out of range")]
    OutOfRange,
}

/// Relocate a single instruction which starts at `pc`.
///
/// This is intentionally conservative: instructions not yet supported return
/// `RelocError::Unsupported` instead of being copied verbatim.
pub fn relocate_one(word: u32, pc: usize) -> Result<Relocated, RelocError> {
    let insn = classify(word);
    let mut w = CodeWriter::new();

    match insn {
        Insn::Nop | Insn::Bti | Insn::Ret { .. } | Insn::Br { .. } | Insn::Blr { .. } => {
            w.put(word);
        }
        Insn::B { offset } => {
            let target = pc.wrapping_add(offset as usize);
            w.abs_b(target);
        }
        Insn::Bl { offset } => {
            let target = pc.wrapping_add(offset as usize);
            w.abs_bl(target);
        }
        Insn::BCond { cond, offset } => {
            if cond >= 0xE {
                return Err(RelocError::Unsupported(word));
            }
            let target = pc.wrapping_add(offset as usize);
            // Invert the condition to skip the absolute branch, then jump.
            if !w.b_cond(cond ^ 1, 20) {
                return Err(RelocError::OutOfRange);
            }
            w.abs_b(target);
        }
        Insn::Cbz {
            sf,
            nonzero,
            rt,
            offset,
        } => {
            let target = pc.wrapping_add(offset as usize);
            if !w.cbz(sf, !nonzero, rt, 20) {
                return Err(RelocError::OutOfRange);
            }
            w.abs_b(target);
        }
        Insn::Tbz {
            op,
            rt,
            bit,
            offset,
        } => {
            let target = pc.wrapping_add(offset as usize);
            if !w.tbz(!op, rt, bit, 20) {
                return Err(RelocError::OutOfRange);
            }
            w.abs_b(target);
        }
        Insn::Adr { rd, offset } => {
            let target = pc.wrapping_add(offset as usize);
            w.abs_addr(rd, target as u64);
        }
        Insn::Adrp { rd, offset } => {
            let base = (pc & !0xFFF) as i64;
            let target = base.wrapping_add(offset);
            w.abs_addr(rd, target as u64);
        }
        Insn::LdrLiteral {
            rt,
            offset,
            is_64,
            is_signed,
            is_prfm,
        } => {
            if is_prfm {
                return Err(RelocError::Unsupported(word));
            }
            let target = pc.wrapping_add(offset as usize) as u64;
            // Preserve a scratch register while materialising the literal
            // address, then load from it.  This avoids copying target bytes
            // into the trampoline and works for any target address.
            let scratch = if rt == 16 { 17 } else { 16 };
            w.put(0xF81F_0FE0 | scratch as u32); // str x<scratch>, [sp, #-16]!
            w.abs_addr(scratch, target);
            if is_signed {
                w.put(0xB980_0000 | ((scratch as u32) << 5) | rt as u32); // ldrsw x<rt>, [x<scratch>]
            } else if is_64 {
                w.put(0xF940_0000 | ((scratch as u32) << 5) | rt as u32); // ldr x<rt>, [x<scratch>]
            } else {
                w.put(0xB940_0000 | ((scratch as u32) << 5) | rt as u32); // ldr w<rt>, [x<scratch>]
            }
            w.put(0xF841_07E0 | scratch as u32); // ldr x<scratch>, [sp], #16
        }
        // Anything we did not classify is treated as position-independent and
        // copied verbatim.  All known PC-relative forms are classified above;
        // PRFM-literal is rejected explicitly.
        Insn::Other(_) => w.put(word),
    }

    Ok(Relocated {
        bytes: w.into_bytes(),
        consumed: 4,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn copies_simple_instructions() {
        for (word, pc) in [
            (0xD503_201F, 0x1000),
            (0xD503_245F, 0x1000),
            (0xD65F_03C0, 0x1000),
            (0xD61F_0200, 0x1000),
            (0xD63F_0220, 0x1000),
        ] {
            let r = relocate_one(word, pc).unwrap();
            assert_eq!(r.consumed, 4);
            assert_eq!(r.bytes, word.to_le_bytes());
        }
    }

    #[test]
    fn relocates_branch_to_target() {
        // bl #0x1000 from pc 0x2000 -> target 0x3000.
        let r = relocate_one(0x9400_0400, 0x2000).unwrap();
        assert_eq!(r.consumed, 4);
        assert_eq!(r.bytes.len(), 24);
        let target = u64::from_le_bytes(r.bytes[16..24].try_into().unwrap());
        assert_eq!(target, 0x3000);
    }

    #[test]
    fn relocates_conditional_branch() {
        // b.eq #0x1000 from pc 0x2000 -> target 0x3000.
        let r = relocate_one(0x5400_8000, 0x2000).unwrap();
        assert_eq!(r.consumed, 4);
        assert_eq!(r.bytes.len(), 20);
        let target = u64::from_le_bytes(r.bytes[12..20].try_into().unwrap());
        assert_eq!(target, 0x3000);
    }

    #[test]
    fn relocates_adr_and_adrp() {
        let r = relocate_one(0x1000_0000, 0x1000).unwrap();
        assert_eq!(r.bytes.len(), 16);
        let r = relocate_one(0x9000_0000, 0x1000).unwrap();
        assert_eq!(r.bytes.len(), 16);
    }

    #[test]
    fn relocates_ldr_literal() {
        // ldr x0, #8 from pc 0x1000.
        let r = relocate_one(0x5800_0040, 0x1000).unwrap();
        assert_eq!(r.bytes.len(), 28);
    }

    #[test]
    fn rejects_unsupported() {
        assert!(relocate_one(0xD503_201F, 0x1000).is_ok());
        assert!(matches!(
            relocate_one(0xD800_0000, 0x1000),
            Err(RelocError::Unsupported(_))
        ));
    }
}
