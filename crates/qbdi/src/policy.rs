//! Decisions the QBDI callbacks apply: PAC-hint skip, escape resume, and
//! call/return stack transfer. No VM handle, so host tests can call them.

/// `EXEC_TRANSFER_CALL` from QBDI's `VMEvent`.
pub const EXEC_TRANSFER_CALL: u32 = 1 << 5;
/// `EXEC_TRANSFER_RETURN` from QBDI's `VMEvent`.
pub const EXEC_TRANSFER_RETURN: u32 = 1 << 6;

const PAC_HINTS: [u32; 8] = [
    0xD503_233F, // PACIASP
    0xD503_237F, // PACIBSP
    0xD503_23BF, // AUTIASP
    0xD503_23FF, // AUTIBSP
    0xD503_231F, // PACIAZ
    0xD503_235F, // PACIBZ
    0xD503_239F, // AUTIAZ
    0xD503_23DF, // AUTIBZ
];

/// True when `word` is a PAC hint that must not run as an instrumented patch.
pub fn is_pac_hint(word: u32) -> bool {
    PAC_HINTS.contains(&word)
}

/// Resume address when `pc` is an escape break, ignoring pointer-auth bits.
pub fn escape_resume(escapes: &[(u64, u64)], pc: u64) -> Option<u64> {
    let pc = pc & 0x0000_FFFF_FFFF_FFFF;
    escapes.iter().find_map(|(break_at, resume)| {
        (*break_at & 0x0000_FFFF_FFFF_FFFF == pc).then_some(*resume)
    })
}

/// Top of the host stack used only by `qbdi_run`, 16-byte aligned.
/// The guest GPR `SP` is not this address.
pub fn aligned_stack_top(base: usize, size: usize) -> usize {
    (base + size) & !15
}

/// Stack pointer after an execution transfer.
///
/// A call keeps the guest stack and remembers it. A return puts that saved
/// pointer back so the instrumented caller is not left on the callee's frame.
pub fn apply_transfer(event: u32, sp: u64, saved: u64) -> (u64, u64) {
    if event & EXEC_TRANSFER_CALL != 0 {
        (sp, sp)
    } else if event & EXEC_TRANSFER_RETURN != 0 && saved != 0 {
        (saved, saved)
    } else {
        (sp, saved)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn pac_hints_are_skipped_and_other_words_are_not() {
        for word in PAC_HINTS {
            assert!(is_pac_hint(word), "{word:#x}");
        }
        assert!(!is_pac_hint(0xD503_201F), "nop");
        assert!(!is_pac_hint(0xD65F_03C0), "ret");
    }

    #[test]
    fn escape_resume_matches_the_break_address() {
        let escapes = [(0x1000, 0x2000), (0x0030_0000_0000_3000, 0x4000)];
        assert_eq!(escape_resume(&escapes, 0x1000), Some(0x2000));
        assert_eq!(
            escape_resume(&escapes, 0x3000),
            Some(0x4000),
            "PAC bits in the break address are ignored"
        );
        assert_eq!(escape_resume(&escapes, 0x1800), None);
    }

    #[test]
    fn transfer_remembers_the_call_stack_and_restores_it() {
        let (sp, saved) = apply_transfer(EXEC_TRANSFER_CALL, 0x7fff_0000, 0);
        assert_eq!((sp, saved), (0x7fff_0000, 0x7fff_0000));
        let (sp, saved) = apply_transfer(EXEC_TRANSFER_RETURN, 0x1000, saved);
        assert_eq!((sp, saved), (0x7fff_0000, 0x7fff_0000));
        let (sp, saved) = apply_transfer(0, 0x55, 0x66);
        assert_eq!((sp, saved), (0x55, 0x66));
    }

    #[test]
    fn host_stack_top_is_aligned_and_not_the_guest_base() {
        let base = 0x1000usize;
        let size = 0x10000usize;
        let top = aligned_stack_top(base, size);
        assert_eq!(top & 15, 0);
        assert_ne!(top, base);
        assert!(top <= base + size);
    }
}
