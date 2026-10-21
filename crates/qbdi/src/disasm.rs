//! AArch64 disassembly for debug execution transfers.
//!
//! Uses the pure-Rust decoder in `arch-arm64`; the agent already links Gum's
//! C capstone through frida-gum, so a second capstone would collide.

#![cfg_attr(not(feature = "vm"), allow(dead_code))]

pub fn disassemble(addr: u64) -> Option<String> {
    let mut bytes = [0u8; 4];
    // SAFETY: debug transfers pass the guest PC, which is an executable instruction.
    unsafe { std::ptr::copy_nonoverlapping(addr as *const u8, bytes.as_mut_ptr(), 4) };
    let decoded = arch_arm64::disasm::decode(u32::from_le_bytes(bytes), addr);
    if decoded.op_str.is_empty() {
        Some(decoded.mnemonic)
    } else {
        Some(format!("{} {}", decoded.mnemonic, decoded.op_str))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn decodes_nop() {
        let nop = [0x1fu8, 0x20, 0x03, 0xd5];
        let addr = nop.as_ptr() as u64;
        let text = disassemble(addr).unwrap_or_else(|| format!("none:{nop:?}"));
        assert_eq!(text, "nop", "bytes {nop:?}");
    }
}
