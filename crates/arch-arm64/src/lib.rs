//! ARM64 support for CommAnalyser.
//!
//! The initial milestone only classifies the instructions that matter for
//! prologue relocation and emits the absolute-branch sequences used by the
//! inline hook.  Coverage grows together with the relocator tests.

pub mod disasm;
pub mod insn;
pub mod relocator;
pub mod writer;

pub use disasm::{decode, Decoded, Operand};
pub use insn::{classify, Insn};
pub use relocator::{relocate_one, Relocated};
pub use writer::CodeWriter;

/// Sign-extend the low `bits` bits of `value`.
#[inline]
pub const fn sign_extend(value: u64, bits: u32) -> i64 {
    let shift = 64 - bits;
    ((value << shift) as i64) >> shift
}

#[cfg(test)]
mod tests {
    #[test]
    fn sign_extension() {
        assert_eq!(super::sign_extend(0b1111, 4), -1);
        assert_eq!(super::sign_extend(0b0111, 4), 7);
        assert_eq!(super::sign_extend(0x3ffff, 19), 0x3ffff);
        assert_eq!(super::sign_extend(0x40000, 19), -0x40000);
    }
}
