//! ARM64 code writer / relocator exposed to JavaScript.

use std::collections::HashMap;

use rquickjs::class::{Trace, Tracer};
use rquickjs::{ArrayBuffer, Class, Ctx, JsLifetime, Object, Result as JsResult, Value};

use arch_arm64::relocator::relocate_one;
use arch_arm64::writer::CodeWriter;
use gum::memory;

use crate::api::parse_pointer;

#[derive(Clone, Copy)]
enum LabelKind {
    B,
    BCond(u8),
    Cbz { sf: bool, nonzero: bool, rt: u8 },
    Tbz { op: bool, rt: u8, bit: u8 },
}

struct LabelRef {
    offset: usize,
    kind: LabelKind,
    label: String,
}

/// JavaScript `Arm64Writer`.
#[derive(JsLifetime)]
#[rquickjs::class(rename_all = "camelCase")]
pub struct Arm64Writer {
    base: u64,
    pc: u64,
    code: CodeWriter,
    labels: HashMap<String, usize>,
    refs: Vec<LabelRef>,
}

impl<'js> Trace<'js> for Arm64Writer {
    fn trace<'a>(&self, _tracer: Tracer<'a, 'js>) {}
}

impl Arm64Writer {
    fn new_at(code: u64, pc: u64) -> Self {
        Self {
            base: code,
            pc,
            code: CodeWriter::with_capacity(256),
            labels: HashMap::new(),
            refs: Vec::new(),
        }
    }

    fn pc_now(&self) -> u64 {
        self.pc + self.code.len() as u64
    }
}

#[rquickjs::methods(rename_all = "camelCase")]
impl Arm64Writer {
    #[qjs(constructor)]
    pub fn new(code: Value<'_>, options: rquickjs::function::Opt<Object<'_>>) -> JsResult<Self> {
        let base = parse_pointer(&code)?;
        let pc = if let Some(options) = options.0 {
            let value: Value<'_> = options.get("pc")?;
            if value.is_undefined() {
                base
            } else {
                parse_pointer(&value)?
            }
        } else {
            base
        };
        Ok(Self::new_at(base, pc))
    }

    #[qjs(get)]
    pub fn offset(&self) -> u32 {
        self.code.len() as u32
    }

    pub fn flush(&mut self) -> JsResult<()> {
        let bytes = self.code.bytes().to_vec();
        for reference in &self.refs {
            let Some(&target) = self.labels.get(&reference.label) else {
                continue;
            };
            let delta = target as i64 - reference.offset as i64;
            let insn = encode_label(reference.kind, delta);
            let start = reference.offset;
            if start + 4 <= bytes.len() {
                // patch after we copy — rebuild below
            }
            let _ = insn;
        }
        let mut patched = bytes;
        for reference in &self.refs {
            let Some(&target) = self.labels.get(&reference.label) else {
                continue;
            };
            let delta = target as i64 - reference.offset as i64;
            let insn = encode_label(reference.kind, delta);
            patched[reference.offset..reference.offset + 4].copy_from_slice(&insn.to_le_bytes());
        }
        memory::write(self.base as usize, &patched).map_err(map_err)?;
        gum::memory::flush_icache(self.base as usize, patched.len());
        Ok(())
    }

    pub fn put_bytes(&mut self, data: ArrayBuffer<'_>) -> JsResult<()> {
        // SAFETY: the ArrayBuffer is a live JS value for the duration of this call.
        self.code
            .put_bytes(unsafe { data.as_bytes() }.unwrap_or(&[]));
        Ok(())
    }

    pub fn put_nop(&mut self) {
        self.code.nop();
    }

    pub fn put_brk_imm(&mut self, imm: rquickjs::function::Opt<u32>) {
        let imm16 = imm.0.unwrap_or(0) & 0xffff;
        self.code.put(0xD420_0000 | (imm16 << 5));
    }

    pub fn put_ret(&mut self) {
        self.code.ret(30);
    }

    pub fn put_mov_reg_reg(&mut self, dst: String, src: String) -> JsResult<()> {
        let (sf_d, rd) = parse_xw(&dst)?;
        let (sf_s, rs) = parse_xw(&src)?;
        let sf = u32::from(sf_d || sf_s) << 31;
        self.code
            .put(sf | 0x2A00_03E0 | ((rs as u32) << 16) | rd as u32);
        Ok(())
    }

    pub fn put_cmp_reg_reg(&mut self, a: String, b: String) -> JsResult<()> {
        let (_, ra) = parse_xw(&a)?;
        let (_, rb) = parse_xw(&b)?;
        // SUBS XZR, Xa, Xb
        self.code
            .put(0xEB00_0000 | ((rb as u32) << 16) | ((ra as u32) << 5) | 31);
        Ok(())
    }

    pub fn put_branch_address(&mut self, address: Value<'_>) -> JsResult<()> {
        self.code.abs_b(parse_pointer(&address)? as usize);
        Ok(())
    }

    pub fn put_sub_reg_reg_imm(&mut self, rd: String, rn: String, imm: u32) -> JsResult<()> {
        let rd = parse_x(&rd)?;
        let rn = parse_x(&rn)?;
        self.code
            .put(0xD100_0000 | (imm << 10) | ((rn as u32) << 5) | rd as u32);
        Ok(())
    }

    pub fn put_add_reg_reg_imm(&mut self, rd: String, rn: String, imm: u32) -> JsResult<()> {
        self.code.add_imm(parse_x(&rd)?, parse_x(&rn)?, imm);
        Ok(())
    }

    pub fn put_ldr_reg_reg_offset(&mut self, rt: String, rn: String, offset: i64) -> JsResult<()> {
        let is_32 = rt.starts_with('w');
        let rt = parse_x(&rt)?;
        let rn = parse_x(&rn)?;
        if offset >= 0 && offset % 8 == 0 && !is_32 {
            self.code.ldr_imm(rt, rn, offset as u32);
        } else {
            let size = if is_32 { 0xB8u32 } else { 0xF8 };
            let imm9 = (offset as u32) & 0x1FF;
            self.code
                .put((size << 24) | (1 << 22) | (imm9 << 12) | ((rn as u32) << 5) | rt as u32);
        }
        Ok(())
    }

    pub fn put_bl_imm(&mut self, address: Value<'_>) -> JsResult<()> {
        let target = parse_pointer(&address)? as i64;
        let delta = target - self.pc_now() as i64;
        if !self.code.bl_imm(delta) {
            let scratch = 16;
            self.code.abs_addr(scratch, target as u64);
            self.code.blr(scratch);
        }
        Ok(())
    }

    pub fn put_br_reg(&mut self, reg: String) -> JsResult<()> {
        self.code.br(parse_x(&reg)?);
        Ok(())
    }

    pub fn put_blr_reg(&mut self, reg: String) -> JsResult<()> {
        self.code.blr(parse_x(&reg)?);
        Ok(())
    }

    pub fn put_ldr_reg_address(&mut self, reg: String, address: Value<'_>) -> JsResult<()> {
        let rd = parse_x(&reg)?;
        let target = parse_pointer(&address)?;
        self.code.abs_addr(rd, target);
        Ok(())
    }

    pub fn put_adrp_reg_address(&mut self, reg: String, address: Value<'_>) -> JsResult<()> {
        let rd = parse_x(&reg)?;
        let target = parse_pointer(&address)?;
        if !self.code.adrp(rd, self.pc_now(), target) {
            self.code.abs_addr(rd, target);
        }
        Ok(())
    }

    pub fn put_push_reg_reg(&mut self, a: String, b: String) -> JsResult<()> {
        if a.starts_with('d') {
            let da = parse_d(&a)?;
            let db = parse_d(&b)?;
            let imm7 = ((-16i64 / 8) as u32) & 0x7F;
            self.code
                .put(0x6D80_0000 | (imm7 << 15) | ((db as u32) << 10) | (31 << 5) | da as u32);
            return Ok(());
        }
        self.code.stp_pre(parse_x(&a)?, parse_x(&b)?, 31, -16);
        Ok(())
    }

    pub fn put_pop_reg_reg(&mut self, a: String, b: String) -> JsResult<()> {
        if a.starts_with('d') {
            let da = parse_d(&a)?;
            let db = parse_d(&b)?;
            let imm7 = (16i64 / 8) as u32 & 0x7F;
            self.code
                .put(0x6CC0_0000 | (imm7 << 15) | ((db as u32) << 10) | (31 << 5) | da as u32);
            return Ok(());
        }
        self.code.ldp_post(parse_x(&a)?, parse_x(&b)?, 31, 16);
        Ok(())
    }

    pub fn put_push_all_x_registers(&mut self) {
        for pair in 0..15u8 {
            self.code.stp_pre(pair * 2, pair * 2 + 1, 31, -16);
        }
        self.code.stp_pre(30, 15, 31, -16);
    }

    pub fn put_pop_all_x_registers(&mut self) {
        self.code.ldp_post(30, 15, 31, 16);
        for pair in (0..15u8).rev() {
            self.code.ldp_post(pair * 2, pair * 2 + 1, 31, 16);
        }
    }

    /// str rt, [rn + offset].
    ///
    /// Chooses the cheapest encoding: scaled STR, then unscaled STUR
    /// (-256..=255, any alignment), then a scratch-register fallback.
    ///
    /// # Side effect
    ///
    /// For offsets that neither STR nor STUR can encode (for example 257,
    /// -1000, or a 32-bit offset of 16384 and above) the writer computes the
    /// address in **x16** and stores at offset 0. If either operand is x16 it
    /// uses **x17** instead. Aligned/small offsets never touch another
    /// register. When both x16 and x17 are operands the call throws rather
    /// than clobbering one of them.
    ///
    /// ```js
    /// const w = new Arm64Writer(code);
    /// w.putStrRegRegOffset("x0", "x1", 8);      // str x0, [x1, #8]  no scratch
    /// w.putStrRegRegOffset("x0", "x1", -1000);  // x16 = x1 - 1000; str x0, [x16]
    /// ```
    ///
    /// Both calls are executed on a device by
    /// `writer::tests::js_layer_falls_back_for_large_store_offsets` (run with
    /// `--target aarch64-linux-android --features gum/link`, see
    /// docs/21-hardening.md).
    pub fn put_str_reg_reg_offset(&mut self, rt: String, rn: String, offset: i64) -> JsResult<()> {
        let is_32 = rt.starts_with('w');
        if !self
            .code
            .str_reg_offset(parse_x(&rt)?, parse_x(&rn)?, offset, is_32)
        {
            return Err(js_err(
                "strRegOffset: offset does not fit STR/STUR immediate encoding",
            ));
        }
        Ok(())
    }

    pub fn put_label(&mut self, label: String) {
        self.labels.insert(label, self.code.len());
    }

    pub fn put_b_label(&mut self, label: String) {
        self.refs.push(LabelRef {
            offset: self.code.len(),
            kind: LabelKind::B,
            label,
        });
        self.code.b_imm(0);
    }

    pub fn put_b_cond_label(&mut self, cond: String, label: String) -> JsResult<()> {
        let cond = parse_cond(&cond)?;
        self.refs.push(LabelRef {
            offset: self.code.len(),
            kind: LabelKind::BCond(cond),
            label,
        });
        self.code.b_cond(cond, 0);
        Ok(())
    }

    /// Frida's wide conditional branch; ARM64 encodings are already 32-bit.
    pub fn put_b_cond_label_wide(&mut self, cond: String, label: String) -> JsResult<()> {
        self.put_b_cond_label(cond, label)
    }

    pub fn dispose(&mut self) -> JsResult<()> {
        self.flush()
    }

    pub fn put_cbz_reg_label(&mut self, reg: String, label: String) -> JsResult<()> {
        let (sf, rt) = parse_xw(&reg)?;
        self.refs.push(LabelRef {
            offset: self.code.len(),
            kind: LabelKind::Cbz {
                sf,
                nonzero: false,
                rt,
            },
            label,
        });
        self.code.cbz(sf, false, rt, 0);
        Ok(())
    }

    pub fn put_cbnz_reg_label(&mut self, reg: String, label: String) -> JsResult<()> {
        let (sf, rt) = parse_xw(&reg)?;
        self.refs.push(LabelRef {
            offset: self.code.len(),
            kind: LabelKind::Cbz {
                sf,
                nonzero: true,
                rt,
            },
            label,
        });
        self.code.cbz(sf, true, rt, 0);
        Ok(())
    }

    pub fn put_tbz_reg_imm_label(&mut self, reg: String, bit: i32, label: String) -> JsResult<()> {
        let rt = parse_x(&reg)?;
        self.refs.push(LabelRef {
            offset: self.code.len(),
            kind: LabelKind::Tbz {
                op: false,
                rt,
                bit: bit as u8,
            },
            label,
        });
        self.code.tbz(false, rt, bit as u8, 0);
        Ok(())
    }

    pub fn put_tbnz_reg_imm_label(&mut self, reg: String, bit: i32, label: String) -> JsResult<()> {
        let rt = parse_x(&reg)?;
        self.refs.push(LabelRef {
            offset: self.code.len(),
            kind: LabelKind::Tbz {
                op: true,
                rt,
                bit: bit as u8,
            },
            label,
        });
        self.code.tbz(true, rt, bit as u8, 0);
        Ok(())
    }

    pub fn put_call_address_with_arguments(
        &mut self,
        address: Value<'_>,
        args: Value<'_>,
    ) -> JsResult<()> {
        let target = parse_pointer(&address)?;
        let list: rquickjs::Array<'_> = args.get()?;
        if list.len() > 8 {
            return Err(js_err(
                "putCallAddressWithArguments: at most 8 arguments (stack arguments are not supported)",
            ));
        }
        // Registers are moved in parallel before immediates: an immediate
        // writes its destination directly, so emitting it in argument order
        // could clobber a source that a later move still needs.
        let mut sources: Vec<Option<u8>> = vec![None; list.len()];
        let mut immediates: Vec<(u8, u64)> = Vec::new();
        for index in 0..list.len() {
            let arg: Value<'_> = list.get(index)?;
            if arg.is_string() {
                sources[index] = Some(parse_x(&arg.get::<String>()?)?);
            } else {
                immediates.push((index as u8, parse_pointer(&arg)?));
            }
        }
        if !self.code.move_arg_registers(&sources) {
            return Err(js_err(
                "putCallAddressWithArguments: argument moves cannot be scheduled",
            ));
        }
        for (destination, value) in immediates {
            self.code.abs_addr(destination, value);
        }
        let scratch = list.len() as u8;
        self.code.abs_addr(scratch, target);
        self.code.blr(scratch);
        Ok(())
    }
}


fn encode_label(kind: LabelKind, delta: i64) -> u32 {
    match kind {
        LabelKind::B => 0x1400_0000 | (((delta >> 2) as u32) & 0x03FF_FFFF),
        LabelKind::BCond(cond) => {
            0x5400_0000 | ((((delta >> 2) as u32) & 0x7_FFFF) << 5) | cond as u32
        }
        LabelKind::Cbz { sf, nonzero, rt } => {
            let mut word = 0x3400_0000 | ((((delta >> 2) as u32) & 0x7_FFFF) << 5) | rt as u32;
            if sf {
                word |= 1 << 31;
            }
            if nonzero {
                word |= 1 << 24;
            }
            word
        }
        LabelKind::Tbz { op, rt, bit } => {
            let mut word = 0x3600_0000
                | ((((delta >> 2) as u32) & 0x3FFF) << 5)
                | rt as u32
                | (((bit as u32) & 0x1F) << 19)
                | (((bit as u32) & 0x20) << 26);
            if op {
                word |= 1 << 24;
            }
            word
        }
    }
}

fn parse_d(name: &str) -> JsResult<u8> {
    let rest = name
        .strip_prefix('d')
        .ok_or_else(|| js_err("bad SIMD register"))?;
    rest.parse().map_err(|_| js_err("bad SIMD register"))
}

fn parse_x(name: &str) -> JsResult<u8> {
    Ok(parse_xw(name)?.1)
}

fn parse_xw(name: &str) -> JsResult<(bool, u8)> {
    let name = name.trim().to_ascii_lowercase();
    match name.as_str() {
        "sp" | "wsp" => return Ok((true, 31)),
        "lr" | "x30" => return Ok((true, 30)),
        "fp" | "x29" => return Ok((true, 29)),
        "xzr" | "wzr" => return Ok((name.starts_with('x'), 31)),
        _ => {}
    }
    if let Some(rest) = name.strip_prefix('x') {
        let n: u8 = rest.parse().map_err(|_| js_err("bad register"))?;
        // x31 is only reachable through the sp/xzr aliases; anything above it
        // would shift into the neighbouring encoding fields and corrupt the
        // instruction instead of failing.
        if n > 30 {
            return Err(js_err("register out of range"));
        }
        return Ok((true, n));
    }
    if let Some(rest) = name.strip_prefix('w') {
        let n: u8 = rest.parse().map_err(|_| js_err("bad register"))?;
        if n > 30 {
            return Err(js_err("register out of range"));
        }
        return Ok((false, n));
    }
    Err(js_err("bad register"))
}

fn parse_cond(name: &str) -> JsResult<u8> {
    let idx = [
        "eq", "ne", "hs", "lo", "mi", "pl", "vs", "vc", "hi", "ls", "ge", "lt", "gt", "le", "al",
        "nv",
    ]
    .iter()
    .position(|c| *c == name)
    .or_else(|| {
        [
            "eq", "ne", "cs", "cc", "mi", "pl", "vs", "vc", "hi", "ls", "ge", "lt", "gt", "le",
        ]
        .iter()
        .position(|c| *c == name)
    });
    idx.map(|v| v as u8).ok_or_else(|| js_err("bad cond"))
}

fn js_err(message: &str) -> rquickjs::Error {
    rquickjs::Error::new_from_js_message("comm-analyser", "writer", message.to_owned())
}

fn map_err(error: impl std::fmt::Display) -> rquickjs::Error {
    rquickjs::Error::new_from_js_message("comm-analyser", "writer", error.to_string())
}

fn relocate_bytes(word: u32, pc: usize) -> Vec<u8> {
    match relocate_one(word, pc) {
        Ok(relocated) => relocated.bytes,
        Err(_) => word.to_le_bytes().to_vec(),
    }
}

/// Install `Arm64Writer` / `Arm64Relocator` globals.
pub fn install<'js>(ctx: &Ctx<'js>) -> JsResult<()> {
    Class::<Arm64Writer>::define(&ctx.globals())?;
    ctx.globals().set(
        "__analyserMakeRelocator",
        rquickjs::Function::new(
            ctx.clone(),
            |ctx: Ctx<'js>,
             input: Value<'js>,
             output: Class<'js, Arm64Writer>|
             -> JsResult<Object<'js>> {
                let start = parse_pointer(&input)? as usize;
                let reloc = Object::new(ctx.clone())?;
                let cursor = std::rc::Rc::new(std::cell::Cell::new(start));
                let eoi = std::rc::Rc::new(std::cell::Cell::new(false));
                let last = std::rc::Rc::new(std::cell::Cell::new((0u32, start)));
                reloc.set("eoi", false)?;
                reloc.set("input", Object::new(ctx.clone())?)?;

                let cursor_r = cursor.clone();
                let eoi_r = eoi.clone();
                let last_r = last.clone();
                let reloc_r = reloc.clone();
                reloc.set(
                    "readOne",
                    rquickjs::Function::new(ctx.clone(), move |ctx: Ctx<'js>| -> JsResult<u32> {
                        if eoi_r.get() {
                            return Ok(0);
                        }
                        let pc = cursor_r.get();
                        let bytes = memory::read(pc, 4).map_err(map_err)?;
                        let word = u32::from_le_bytes(
                            bytes.as_slice().try_into().map_err(|_| {
                                js_err("readOne: instruction crosses a mapping boundary")
                            })?,
                        );
                        last_r.set((word, pc));
                        cursor_r.set(pc + 4);
                        let insn = arch_arm64::classify(word);
                        if insn.is_branch() && !matches!(insn, arch_arm64::Insn::Bl { .. }) {
                            eoi_r.set(true);
                            reloc_r.set("eoi", true)?;
                        }
                        let decoded = arch_arm64::decode(word, pc as u64);
                        reloc_r.set(
                            "input",
                            crate::instruction::from_decoded(ctx, pc as u64, &decoded)?,
                        )?;
                        Ok((cursor_r.get() - start) as u32)
                    })?,
                )?;
                let last_w = last.clone();
                let out_w = output.clone();
                reloc.set(
                    "writeOne",
                    rquickjs::Function::new(ctx.clone(), move || -> JsResult<bool> {
                        let (word, pc) = last_w.get();
                        out_w.borrow_mut().code.put_bytes(&relocate_bytes(word, pc));
                        Ok(true)
                    })?,
                )?;
                reloc.set(
                    "writeAll",
                    rquickjs::Function::new(ctx.clone(), {
                        let last_w = last.clone();
                        let out_w = output.clone();
                        move || -> JsResult<()> {
                            let (word, pc) = last_w.get();
                            out_w.borrow_mut().code.put_bytes(&relocate_bytes(word, pc));
                            Ok(())
                        }
                    })?,
                )?;
                reloc.set("skipOne", rquickjs::Function::new(ctx.clone(), || {})?)?;
                reloc.set("dispose", rquickjs::Function::new(ctx.clone(), || {})?)?;
                Ok(reloc)
            },
        ),
    )?;
    ctx.eval::<(), _>(
        r#"
        globalThis.Arm64Relocator = function (input, output) {
            return __analyserMakeRelocator(input, output);
        };
        "#,
    )?;
    Ok(())
}
#[cfg(test)]
mod tests {
    use super::*;
    use rquickjs::{Context, Runtime};

    /// Emit code through the JS API and return the writer bytes.
    fn emit(script: &str) -> rquickjs::Result<Vec<u8>> {
        let runtime = Runtime::new()?;
        let ctx = Context::full(&runtime)?;
        let mut sink = vec![0u8; 256];
        let base = sink.as_mut_ptr() as u64;
        ctx.with(|ctx| {
            install(&ctx)?;
            ctx.globals().set("base", base)?;
            ctx.eval::<(), _>(script)?;
            let writer: Class<Arm64Writer> = ctx.eval("w")?;
            let bytes = {
                let borrow = writer.borrow();
                borrow.code.bytes().to_vec()
            };
            Ok(bytes)
        })
    }

    /// Apply the emitted moves to a register file, stopping at the call.
    fn simulate(bytes: &[u8]) -> [u64; 32] {
        let mut regs: [u64; 32] = core::array::from_fn(|index| 0x1000 + index as u64);
        let sp = 0x7000u64;
        for word in bytes.chunks_exact(4).map(|chunk| {
            u32::from_le_bytes(chunk.try_into().expect("4-byte chunk"))
        }) {
            let rd = (word & 0x1F) as usize;
            let rn = ((word >> 5) & 0x1F) as usize;
            let rm = ((word >> 16) & 0x1F) as usize;
            if word & 0xFFE0_FFE0 == 0xAA00_03E0 {
                // mov xd, xm
                regs[rd] = if rm == 31 { 0 } else { regs[rm] };
            } else if word & 0xFF80_0000 == 0xD280_0000 {
                // movz xd, #imm16, lsl #(hw * 16)
                let imm = ((word >> 5) & 0xFFFF) as u64;
                let shift = ((word >> 21) & 0x3) * 16;
                regs[rd] = imm << shift;
            } else if word & 0xFF80_0000 == 0xF280_0000 {
                // movk
                let imm = ((word >> 5) & 0xFFFF) as u64;
                let shift = ((word >> 21) & 0x3) * 16;
                let mask = !(0xFFFFu64 << shift);
                regs[rd] = (regs[rd] & mask) | (imm << shift);
            } else if word & 0xFFC0_0000 == 0x9100_0000 {
                // add xd, xn|sp, #imm
                let imm = ((word >> 10) & 0xFFF) as u64;
                let base = if rn == 31 { sp } else { regs[rn] };
                regs[rd] = base + imm;
            } else if word & 0xFFFF_FC1F == 0xD63F_0000 {
                // blr xn: arguments are in place, stop before the call.
                break;
            } else {
                panic!("unexpected instruction {word:#010x}");
            }
        }
        regs
    }

    #[test]
    fn js_layer_moves_arguments_in_parallel() {
        // Naive ordering would leave x1 == old x1 instead of old x0.
        let bytes = emit(r#"
            globalThis.w = new Arm64Writer(base);
            w.putCallAddressWithArguments(0x1000, ["x1", "x0"]);
        "#)
        .expect("emit");
        let regs = simulate(&bytes);
        assert_eq!(regs[0], 0x1001, "x0 must receive the old x1");
        assert_eq!(regs[1], 0x1000, "x1 must receive the old x0");
    }

    #[test]
    fn js_layer_breaks_a_three_way_cycle() {
        let bytes = emit(r#"
            globalThis.w = new Arm64Writer(base);
            w.putCallAddressWithArguments(0x2000, ["x2", "x0", "x1"]);
        "#)
        .expect("emit");
        let regs = simulate(&bytes);
        assert_eq!(regs[0], 0x1002);
        assert_eq!(regs[1], 0x1000);
        assert_eq!(regs[2], 0x1001);
    }

    #[test]
    fn js_layer_writes_immediates_after_register_moves() {
        // Immediate first would destroy x0 before the move reads it.
        let bytes = emit(r#"
            globalThis.w = new Arm64Writer(base);
            w.putCallAddressWithArguments(0x3000, [0x1234, "x0"]);
        "#)
        .expect("emit");
        let regs = simulate(&bytes);
        assert_eq!(regs[0], 0x1234);
        assert_eq!(regs[1], 0x1000, "x1 must keep the old x0");
    }

    #[test]
    fn js_layer_rejects_unsupported_argument_shapes() {
        let too_many = emit(r#"
            globalThis.w = new Arm64Writer(base);
            w.putCallAddressWithArguments(0x1000, ["x0","x1","x2","x3","x4","x5","x6","x7","x0"]);
        "#);
        assert!(too_many.is_err(), "9 arguments must be rejected");

        let bad_register = emit(r#"
            globalThis.w = new Arm64Writer(base);
            w.putCallAddressWithArguments(0x1000, ["x99"]);
        "#);
        assert!(bad_register.is_err(), "x99 must be rejected");
    }

    /// Decode a single emitted store into (effective offset, is_32).
    fn decode_store(bytes: &[u8]) -> (i64, bool) {
        assert_eq!(bytes.len(), 4, "expected exactly one instruction");
        let word = u32::from_le_bytes(bytes.try_into().expect("4 bytes"));
        if word & 0xFFC0_0000 == 0xF900_0000 {
            ((((word >> 10) & 0xFFF) * 8) as i64, false)
        } else if word & 0xFFC0_0000 == 0xB900_0000 {
            ((((word >> 10) & 0xFFF) * 4) as i64, true)
        } else if word & 0xFFE0_0C00 == 0xF800_0000 {
            let imm9 = ((word >> 12) & 0x1FF) as i64;
            ((imm9 << 55) >> 55, false)
        } else if word & 0xFFE0_0C00 == 0xB800_0000 {
            let imm9 = ((word >> 12) & 0x1FF) as i64;
            ((imm9 << 55) >> 55, true)
        } else {
            panic!("unexpected store encoding {word:#010x}");
        }
    }

    #[test]
    fn js_layer_preserves_unaligned_store_offsets() {
        // 5 is not a multiple of 8 and must go through STUR unchanged.
        let bytes = emit(r#"
            globalThis.w = new Arm64Writer(base);
            w.putStrRegRegOffset("x0", "x1", 5);
        "#)
        .expect("emit");
        assert_eq!(decode_store(&bytes), (5, false));

        // A 32-bit store gets its own scaled form (scale 4), not a rejection.
        let bytes = emit(r#"
            globalThis.w = new Arm64Writer(base);
            w.putStrRegRegOffset("w0", "x1", 256);
        "#)
        .expect("emit");
        assert_eq!(decode_store(&bytes), (256, true));
    }

    /// Replay a store sequence and return the effective address.
    fn simulate_store(bytes: &[u8]) -> i64 {
        let mut regs: [u64; 32] = core::array::from_fn(|index| 0x1000 + index as u64);
        let mut address = None;
        for word in bytes.chunks_exact(4).map(|chunk| {
            u32::from_le_bytes(chunk.try_into().expect("4 bytes"))
        }) {
            let rd = (word & 0x1F) as usize;
            let base = ((word >> 5) & 0x1F) as usize;
            let rm = ((word >> 16) & 0x1F) as usize;
            if word & 0xFFE0_FFE0 == 0xAA00_03E0 {
                // mov xd, xm
                regs[rd] = regs[rm];
            } else if word & 0xFF80_0000 == 0xD280_0000 {
                let immediate = ((word >> 5) & 0xFFFF) as u64;
                regs[rd] = immediate << (((word >> 21) & 0x3) * 16);
            } else if word & 0xFF80_0000 == 0xF280_0000 {
                let immediate = ((word >> 5) & 0xFFFF) as u64;
                let shift = ((word >> 21) & 0x3) * 16;
                regs[rd] = (regs[rd] & !(0xFFFFu64 << shift)) | (immediate << shift);
            } else if word & 0xFFC0_0000 == 0x9100_0000
                || word & 0xFFC0_0000 == 0x9140_0000
            {
                let immediate = ((word >> 10) & 0xFFF) as u64;
                let shift = if word & 0x0040_0000 != 0 { 12 } else { 0 };
                regs[rd] = regs[base].wrapping_add(immediate << shift);
            } else if word & 0xFFC0_0000 == 0xD100_0000
                || word & 0xFFC0_0000 == 0xD140_0000
            {
                let immediate = ((word >> 10) & 0xFFF) as u64;
                let shift = if word & 0x0040_0000 != 0 { 12 } else { 0 };
                regs[rd] = regs[base].wrapping_sub(immediate << shift);
            } else if word & 0xFFE0_FC00 == 0x8B00_0000 {
                regs[rd] = regs[base].wrapping_add(regs[rm]);
            } else if word & 0xFFC0_0000 == 0xF900_0000 {
                address = Some(regs[base] as i64 + (((word >> 10) & 0xFFF) as i64 * 8));
                break;
            } else if word & 0xFFE0_0C00 == 0xF800_0000 {
                let imm9 = (((word >> 12) & 0x1FF) as i64) << 55 >> 55;
                address = Some(regs[base] as i64 + imm9);
                break;
            } else {
                panic!("unexpected instruction {word:#010x}");
            }
        }
        address.expect("sequence must store once")
    }

    #[test]
    fn js_layer_falls_back_for_large_store_offsets() {
        // -1000 fits neither STR nor STUR; the writer materializes the address
        // in x16 and stores at offset 0.
        let bytes = emit(r#"
            globalThis.w = new Arm64Writer(base);
            w.putStrRegRegOffset("x0", "x1", -1000);
        "#)
        .expect("emit");
        assert!(bytes.len() > 4, "fallback must emit more than one instruction");
        assert_eq!(simulate_store(&bytes), 0x1001 - 1000);
    }

    #[test]
    fn js_layer_rejects_large_offset_without_a_scratch_register() {
        // x16/x17 are the scratch candidates; using both leaves none.
        let result = emit(r#"
            globalThis.w = new Arm64Writer(base);
            w.putStrRegRegOffset("x16", "x17", 5001);
        "#);
        assert!(result.is_err(), "no scratch register available");
    }
}

