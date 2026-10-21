//! `Instruction.parse` for ARM64.

use rquickjs::{Array, Ctx, Object, Result as JsResult, Value};

use arch_arm64::disasm::{decode, Operand};
use arch_arm64::Decoded;
use gum::memory;

use crate::api::{parse_pointer, NativePointer};

pub(crate) fn from_decoded<'js>(
    ctx: Ctx<'js>,
    pc: u64,
    decoded: &Decoded,
) -> JsResult<Object<'js>> {
    let insn = Object::new(ctx.clone())?;
    insn.set("address", NativePointer::instance(ctx.clone(), pc)?)?;
    insn.set(
        "next",
        NativePointer::instance(ctx.clone(), pc + decoded.size as u64)?,
    )?;
    insn.set("size", decoded.size as u32)?;
    insn.set("mnemonic", decoded.mnemonic.clone())?;
    insn.set("opStr", decoded.op_str.clone())?;

    let operands = Array::new(ctx.clone())?;
    for (index, operand) in decoded.operands.iter().enumerate() {
        operands.set(index, operand_object(&ctx, operand)?)?;
    }
    insn.set("operands", operands)?;

    let read = Array::new(ctx.clone())?;
    for (index, name) in decoded.regs_read.iter().enumerate() {
        read.set(index, name.clone())?;
    }
    let written = Array::new(ctx.clone())?;
    for (index, name) in decoded.regs_written.iter().enumerate() {
        written.set(index, name.clone())?;
    }
    let accessed = Object::new(ctx.clone())?;
    accessed.set("read", read)?;
    accessed.set("written", written)?;
    insn.set("regsAccessed", accessed)?;
    insn.set(
        "toString",
        rquickjs::Function::new(ctx.clone(), {
            let text = if decoded.op_str.is_empty() {
                decoded.mnemonic.clone()
            } else {
                format!("{} {}", decoded.mnemonic, decoded.op_str)
            };
            move || text.clone()
        })?,
    )?;
    Ok(insn)
}

/// Parse one ARM64 instruction at `address`.
pub fn parse<'js>(ctx: Ctx<'js>, address: Value<'js>) -> JsResult<Object<'js>> {
    let pc = parse_pointer(&address)?;
    let bytes = memory::read(pc as usize, 4).map_err(|error| {
        rquickjs::Error::new_from_js_message("comm-analyser", "instruction", error.to_string())
    })?;
    // `gum_memory_read` reports a partial read through its out-parameter; a
    // short read must become a JS exception, not a panic across the cdylib.
    let word = u32::from_le_bytes(bytes.as_slice().try_into().map_err(|_| {
        rquickjs::Error::new_from_js_message(
            "comm-analyser",
            "instruction",
            "short read: instruction crosses a mapping boundary".to_owned(),
        )
    })?);
    let decoded = decode(word, pc);
    from_decoded(ctx, pc, &decoded)
}

fn operand_object<'js>(ctx: &Ctx<'js>, operand: &Operand) -> JsResult<Object<'js>> {
    let obj = Object::new(ctx.clone())?;
    match operand {
        Operand::Reg(name) => {
            obj.set("type", "reg")?;
            obj.set("value", name.clone())?;
        }
        Operand::Imm(value) => {
            obj.set("type", "imm")?;
            obj.set("value", *value as f64)?;
        }
        Operand::Mem { base, disp } => {
            obj.set("type", "mem")?;
            let mem = Object::new(ctx.clone())?;
            mem.set("base", base.clone())?;
            mem.set("disp", *disp)?;
            obj.set("value", mem)?;
        }
    }
    Ok(obj)
}
