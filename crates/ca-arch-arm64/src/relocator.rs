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
        Insn::BCond { .. }
        | Insn::Cbz { .. }
        | Insn::Tbz { .. }
        | Insn::Adr { .. }
        | Insn::Adrp { .. }
        | Insn::LdrLiteral { .. }
        | Insn::Other(_) => return Err(RelocError::Unsupported(word)),
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
    fn rejects_unsupported() {
        assert!(matches!(
            relocate_one(0x5400_0000, 0x1000),
            Err(RelocError::Unsupported(_))
        ));
        assert!(matches!(
            relocate_one(0x1000_0000, 0x1000),
            Err(RelocError::Unsupported(_))
        ));
    }
}
