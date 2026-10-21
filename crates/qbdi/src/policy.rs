#![cfg_attr(not(feature = "vm"), allow(dead_code))]

//! Instruction class, break addresses, and printable memory.
//! Same decisions as TAL `Trace::AnalysisInstType`, `CheckAndBreak`, and
//! `IsPrintable` / `PrintStr`. No VM handle.

/// TAL `InstOprandType` without the taint path.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum InstKind {
    None,
    Call,
    Ret,
    Jmp,
    IfJmp,
}

/// `isCall`, else `isReturn`, else `isBranch` (`isPredicable` selects `IfJmp`).
pub fn classify(is_call: bool, is_return: bool, is_branch: bool, is_predicable: bool) -> InstKind {
    if is_call {
        InstKind::Call
    } else if is_return {
        InstKind::Ret
    } else if is_branch && is_predicable {
        InstKind::IfJmp
    } else if is_branch {
        InstKind::Jmp
    } else {
        InstKind::None
    }
}

/// `addr == trace_end`, or `addr` is an escape break.
/// `trace_end == 0` still matches address 0, as in TAL.
pub fn hits_break(addr: u64, trace_end: u64, escapes: &[(u64, u64)]) -> bool {
    addr == trace_end || escapes.iter().any(|(break_at, _)| *break_at == addr)
}

/// TAL `READABLE_ADDR`.
pub const READABLE_ADDR: u64 = 0x3000;

/// `IsPrintable` then `PrintStr`. `None` when the gate fails.
///
/// # Safety
/// `addr` must be readable for `max` bytes (checked below against the page
/// boundary control) -- the printable run that follows is clamped to the same
/// page.
pub unsafe fn printable_text(addr: u64, max: i32) -> Option<String> {
    if max <= 0 || addr <= READABLE_ADDR {
        return None;
    }
    let max = max as usize;
    // The guest just touched this address, so its page is mapped. Never read
    // past that page: the old version scanned until a non-printable byte,
    // which walks into an unmapped page when a string ends a mapping.
    let page = runtime::process::page_size();
    let to_page_end = page - (addr as usize % page);
    if to_page_end < max {
        return None;
    }
    let bytes = addr as *const u8;
    let byte_at = |index: usize| unsafe { bytes.add(index).read_unaligned() };
    for index in 0..max {
        if !(32..=126).contains(&byte_at(index)) {
            return None;
        }
    }
    let mut text = String::new();
    for index in 0..to_page_end {
        let byte = byte_at(index);
        if !(33..=125).contains(&byte) {
            break;
        }
        text.push(byte as char);
    }
    Some(text)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn classifies_like_tal() {
        assert_eq!(classify(true, false, true, false), InstKind::Call);
        assert_eq!(classify(false, true, true, false), InstKind::Ret);
        assert_eq!(classify(false, false, true, true), InstKind::IfJmp);
        assert_eq!(classify(false, false, true, false), InstKind::Jmp);
        assert_eq!(classify(false, false, false, false), InstKind::None);
    }

    #[test]
    fn break_matches_trace_end_and_escape_min() {
        assert!(hits_break(0x20, 0x20, &[]));
        assert!(hits_break(0x30, 0, &[(0x30, 0x40)]));
        assert!(!hits_break(0x10, 0x20, &[(0x30, 0x40)]));
        assert!(hits_break(0, 0, &[]));
    }

    #[test]
    fn printable_requires_a_run_of_max_bytes() {
        let raw = *b"ABCD!\0";
        let addr = raw.as_ptr() as u64;
        assert!(addr > READABLE_ADDR);
        let text = unsafe { printable_text(addr, 4) }.expect("printable");
        assert_eq!(text, "ABCD!");
        assert!(unsafe { printable_text(addr, 0) }.is_none());
        assert!(unsafe { printable_text(0x1000, 4) }.is_none());
    }
}
