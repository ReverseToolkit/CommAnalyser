//! ARM64 instruction text and operands for `Instruction.parse`.
//!
//! Mnemonics and operand shapes follow Frida/Capstone closely enough for
//! frida-java-bridge's ARM64 offset probes.

use crate::insn::{classify, Insn, LiteralSimd};

const XREGS: [&str; 32] = [
    "x0", "x1", "x2", "x3", "x4", "x5", "x6", "x7", "x8", "x9", "x10", "x11", "x12", "x13", "x14",
    "x15", "x16", "x17", "x18", "x19", "x20", "x21", "x22", "x23", "x24", "x25", "x26", "x27",
    "x28", "fp", "lr", "sp",
];
const WREGS: [&str; 32] = [
    "w0", "w1", "w2", "w3", "w4", "w5", "w6", "w7", "w8", "w9", "w10", "w11", "w12", "w13", "w14",
    "w15", "w16", "w17", "w18", "w19", "w20", "w21", "w22", "w23", "w24", "w25", "w26", "w27",
    "w28", "w29", "w30", "wsp",
];
const CONDS: [&str; 16] = [
    "eq", "ne", "hs", "lo", "mi", "pl", "vs", "vc", "hi", "ls", "ge", "lt", "gt", "le", "al", "nv",
];

/// One decoded ARM64 instruction.
#[derive(Clone, Debug)]
pub struct Decoded {
    pub mnemonic: String,
    pub op_str: String,
    pub size: usize,
    pub operands: Vec<Operand>,
    pub regs_read: Vec<String>,
    pub regs_written: Vec<String>,
}

/// Frida-style operand.
#[derive(Clone, Debug)]
pub enum Operand {
    Reg(String),
    Imm(i64),
    Mem { base: String, disp: i32 },
}

/// Decode one 32-bit ARM64 instruction at `pc`.
pub fn decode(word: u32, pc: u64) -> Decoded {
    if let Some(decoded) = decode_classified(word, pc) {
        return decoded;
    }
    decode_data_processing(word).unwrap_or_else(|| unknown(word))
}

fn unknown(word: u32) -> Decoded {
    Decoded {
        mnemonic: "udf".into(),
        op_str: format!("{word:#010x}"),
        size: 4,
        operands: Vec::new(),
        regs_read: Vec::new(),
        regs_written: Vec::new(),
    }
}

fn decode_classified(word: u32, pc: u64) -> Option<Decoded> {
    match classify(word) {
        Insn::Nop => Some(simple("nop", "", vec![], vec![], vec![])),
        Insn::Bti => Some(simple("bti", "c", vec![], vec![], vec![])),
        Insn::B { offset } => {
            let target = pc.wrapping_add(offset as u64) as i64;
            Some(simple(
                "b",
                &format!("{target:#x}"),
                vec![Operand::Imm(target)],
                vec![],
                vec![],
            ))
        }
        Insn::Bl { offset } => {
            let target = pc.wrapping_add(offset as u64) as i64;
            Some(simple(
                "bl",
                &format!("{target:#x}"),
                vec![Operand::Imm(target)],
                vec!["lr".into()],
                vec!["lr".into()],
            ))
        }
        Insn::BCond { cond, offset } => {
            let name = format!("b.{}", CONDS[cond as usize & 0xF]);
            let target = pc.wrapping_add(offset as u64) as i64;
            Some(simple(
                &name,
                &format!("{target:#x}"),
                vec![Operand::Imm(target)],
                vec![],
                vec![],
            ))
        }
        Insn::Cbz {
            sf,
            nonzero,
            rt,
            offset,
        } => {
            let mnemonic = if nonzero { "cbnz" } else { "cbz" };
            let reg = if sf { xreg(rt) } else { wreg(rt) };
            let target = pc.wrapping_add(offset as u64) as i64;
            Some(simple(
                mnemonic,
                &format!("{reg}, {target:#x}"),
                vec![Operand::Reg(reg.into()), Operand::Imm(target)],
                vec![reg.into()],
                vec![],
            ))
        }
        Insn::Tbz {
            op,
            rt,
            bit,
            offset,
        } => {
            let mnemonic = if op { "tbnz" } else { "tbz" };
            let reg = if bit >= 32 { xreg(rt) } else { wreg(rt) };
            let target = pc.wrapping_add(offset as u64) as i64;
            Some(simple(
                mnemonic,
                &format!("{reg}, #{bit}, {target:#x}"),
                vec![
                    Operand::Reg(reg.into()),
                    Operand::Imm(bit as i64),
                    Operand::Imm(target),
                ],
                vec![reg.into()],
                vec![],
            ))
        }
        Insn::Adr { rd, offset } => {
            let target = pc.wrapping_add(offset as u64) as i64;
            Some(simple(
                "adr",
                &format!("{}, {target:#x}", xreg(rd)),
                vec![Operand::Reg(xreg(rd).into()), Operand::Imm(target)],
                vec![],
                vec![xreg(rd).into()],
            ))
        }
        Insn::Adrp { rd, offset } => {
            let base = (pc & !0xfff) as i64;
            let target = base.wrapping_add(offset);
            Some(simple(
                "adrp",
                &format!("{}, {target:#x}", xreg(rd)),
                vec![Operand::Reg(xreg(rd).into()), Operand::Imm(target)],
                vec![],
                vec![xreg(rd).into()],
            ))
        }
        Insn::LdrLiteral {
            rt,
            offset,
            is_64,
            is_signed,
            is_prfm,
        } => {
            if is_prfm {
                return Some(simple("prfm", "", vec![], vec![], vec![]));
            }
            let mnemonic = if is_signed { "ldrsw" } else { "ldr" };
            let reg = if is_64 || is_signed {
                xreg(rt)
            } else {
                wreg(rt)
            };
            let target = pc.wrapping_add(offset as u64) as i64;
            Some(simple(
                mnemonic,
                &format!("{reg}, {target:#x}"),
                vec![Operand::Reg(reg.into()), Operand::Imm(target)],
                vec![],
                vec![reg.into()],
            ))
        }
        Insn::LdrLiteralSimd { rt, offset, kind } => {
            let reg = match kind {
                LiteralSimd::S => format!("s{rt}"),
                LiteralSimd::D => format!("d{rt}"),
                LiteralSimd::Q => format!("q{rt}"),
            };
            let target = pc.wrapping_add(offset as u64) as i64;
            Some(simple(
                "ldr",
                &format!("{reg}, {target:#x}"),
                vec![Operand::Reg(reg.clone()), Operand::Imm(target)],
                vec![],
                vec![reg],
            ))
        }
        Insn::Br { rn } => Some(simple(
            "br",
            xreg(rn),
            vec![Operand::Reg(xreg(rn).into())],
            vec![xreg(rn).into()],
            vec![],
        )),
        Insn::Blr { rn } => Some(simple(
            "blr",
            xreg(rn),
            vec![Operand::Reg(xreg(rn).into())],
            vec![xreg(rn).into(), "lr".into()],
            vec!["lr".into()],
        )),
        Insn::Ret { rn } => Some(simple(
            "ret",
            if rn == 30 { "" } else { xreg(rn) },
            vec![Operand::Reg(xreg(rn).into())],
            vec![xreg(rn).into()],
            vec![],
        )),
        Insn::Other(_) => None,
    }
}

fn decode_data_processing(word: u32) -> Option<Decoded> {
    // LDR/STR unsigned offset: size 111 x0 01 imm12 Rn Rt
    if word & 0x3B00_0000 == 0x3900_0000 {
        let size = (word >> 30) & 3;
        let is_load = (word >> 22) & 1 == 1;
        let opc = (word >> 22) & 3;
        let rn = ((word >> 5) & 0x1F) as u8;
        let rt = (word & 0x1F) as u8;
        let imm12 = (word >> 10) & 0xFFF;
        let scale = size;
        let disp = (imm12 << scale) as i32;
        let (mnemonic, dest) = match (size, opc) {
            (0, 0) => ("strb", wreg(rt)),
            (0, 1) => ("ldrb", wreg(rt)),
            (1, 0) => ("strh", wreg(rt)),
            (1, 1) => ("ldrh", wreg(rt)),
            (2, 0) => ("str", wreg(rt)),
            (2, 1) => ("ldr", wreg(rt)),
            (3, 0) => ("str", xreg(rt)),
            (3, 1) => ("ldr", xreg(rt)),
            _ => return None,
        };
        let base = xreg(rn);
        let op_str = format!("{dest}, [{base}, #{disp}]");
        let mem = Operand::Mem {
            base: base.into(),
            disp,
        };
        let dest_op = Operand::Reg(dest.into());
        return Some(if is_load {
            Decoded {
                mnemonic: mnemonic.into(),
                op_str,
                size: 4,
                operands: vec![dest_op, mem],
                regs_read: vec![base.into()],
                regs_written: vec![dest.into()],
            }
        } else {
            Decoded {
                mnemonic: mnemonic.into(),
                op_str,
                size: 4,
                operands: vec![dest_op, mem],
                regs_read: vec![dest.into(), base.into()],
                regs_written: vec![],
            }
        });
    }

    // ADD/SUB immediate: sf 00 1 0001 0 sh imm12 Rn Rd
    if word & 0x1F00_0000 == 0x1100_0000 {
        let sf = word >> 31 == 1;
        let op = (word >> 30) & 1;
        let s = (word >> 29) & 1;
        let rd = (word & 0x1F) as u8;
        let rn = ((word >> 5) & 0x1F) as u8;
        let imm12 = ((word >> 10) & 0xFFF) as i64;
        let shift = if (word >> 22) & 1 == 1 { 12 } else { 0 };
        let imm = imm12 << shift;
        let dest = if sf { xreg(rd) } else { wreg(rd) };
        let src = if sf { xreg(rn) } else { wreg(rn) };
        if s == 1 && rd == 31 {
            let mnemonic = if op == 1 { "cmp" } else { "cmn" };
            return Some(simple(
                mnemonic,
                &format!("{src}, #{imm}"),
                vec![Operand::Reg(src.into()), Operand::Imm(imm)],
                vec![src.into()],
                vec![],
            ));
        }
        let mnemonic = match (op, s) {
            (0, 0) => "add",
            (0, 1) => "adds",
            (1, 0) => "sub",
            _ => "subs",
        };
        return Some(simple(
            mnemonic,
            &format!("{dest}, {src}, #{imm}"),
            vec![
                Operand::Reg(dest.into()),
                Operand::Reg(src.into()),
                Operand::Imm(imm),
            ],
            vec![src.into()],
            vec![dest.into()],
        ));
    }

    // MOVZ/MOVK/MOVN
    if word & 0x1F80_0000 == 0x1280_0000 {
        let sf = word >> 31 == 1;
        let opc = (word >> 29) & 3;
        let rd = (word & 0x1F) as u8;
        let imm16 = ((word >> 5) & 0xFFFF) as i64;
        let hw = ((word >> 21) & 3) * 16;
        let dest = if sf { xreg(rd) } else { wreg(rd) };
        let mnemonic = match opc {
            0 => "movn",
            2 => "movz",
            3 => "movk",
            _ => return None,
        };
        return Some(simple(
            mnemonic,
            &format!("{dest}, #{imm16}, lsl #{hw}"),
            vec![
                Operand::Reg(dest.into()),
                Operand::Imm(imm16),
                Operand::Imm(hw as i64),
            ],
            vec![],
            vec![dest.into()],
        ));
    }

    // ORR shifted register, used as MOV: sf 01 0 1010 00 Rm 000000 Rn Rd, imm6=0
    if word & 0x7F20_FC00 == 0x2A00_0000 {
        let sf = word >> 31 == 1;
        let rd = (word & 0x1F) as u8;
        let rn = ((word >> 5) & 0x1F) as u8;
        let rm = ((word >> 16) & 0x1F) as u8;
        let dest = if sf { xreg(rd) } else { wreg(rd) };
        if rn == 31 {
            let src = if sf { xreg(rm) } else { wreg(rm) };
            return Some(simple(
                "mov",
                &format!("{dest}, {src}"),
                vec![Operand::Reg(dest.into()), Operand::Reg(src.into())],
                vec![src.into()],
                vec![dest.into()],
            ));
        }
        let src_n = if sf { xreg(rn) } else { wreg(rn) };
        let src_m = if sf { xreg(rm) } else { wreg(rm) };
        return Some(simple(
            "orr",
            &format!("{dest}, {src_n}, {src_m}"),
            vec![
                Operand::Reg(dest.into()),
                Operand::Reg(src_n.into()),
                Operand::Reg(src_m.into()),
            ],
            vec![src_n.into(), src_m.into()],
            vec![dest.into()],
        ));
    }

    None
}

fn simple(
    mnemonic: &str,
    op_str: &str,
    operands: Vec<Operand>,
    regs_read: Vec<String>,
    regs_written: Vec<String>,
) -> Decoded {
    Decoded {
        mnemonic: mnemonic.into(),
        op_str: op_str.into(),
        size: 4,
        operands,
        regs_read,
        regs_written,
    }
}

fn xreg(n: u8) -> &'static str {
    XREGS[(n & 31) as usize]
}

fn wreg(n: u8) -> &'static str {
    WREGS[(n & 31) as usize]
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn decodes_nop_and_ldr_unsigned() {
        let nop = decode(0xD503_201F, 0x1000);
        assert_eq!(nop.mnemonic, "nop");
        // ldr x0, [x1, #24]
        let ldr = decode(0xF940_0C20, 0x1000);
        assert_eq!(ldr.mnemonic, "ldr");
        match &ldr.operands[1] {
            Operand::Mem { base, disp } => {
                assert_eq!(base, "x1");
                assert_eq!(*disp, 24);
            }
            other => panic!("expected mem operand, got {other:?}"),
        }
    }

    #[test]
    fn decodes_bl_and_b_eq() {
        let bl = decode(0x9400_0000, 0x2000);
        assert_eq!(bl.mnemonic, "bl");
        let beq = decode(0x5400_0000, 0x1000);
        assert_eq!(beq.mnemonic, "b.eq");
    }
}
