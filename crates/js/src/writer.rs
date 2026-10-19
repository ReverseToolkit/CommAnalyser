//! ARM64 code writer / relocator exposed to JavaScript.

use std::collections::HashMap;

use rquickjs::class::{Trace, Tracer};
use rquickjs::{ArrayBuffer, Class, Ctx, JsLifetime, Object, Result as JsResult, Value};

use gum::arch::relocator::relocate_one;
use gum::arch::writer::CodeWriter;
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

    pub fn put_str_reg_reg_offset(&mut self, rt: String, rn: String, offset: i64) -> JsResult<()> {
        let is_32 = rt.starts_with('w');
        self.code
            .str_reg_offset(parse_x(&rt)?, parse_x(&rn)?, offset, is_32);
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
        let mut values = Vec::new();
        let list: rquickjs::Array<'_> = args.get()?;
        for index in 0..list.len() {
            let arg: Value<'_> = list.get(index)?;
            if arg.is_string() {
                values.push(RegOrImm::Reg(arg.get::<String>()?));
            } else {
                values.push(RegOrImm::Imm(parse_pointer(&arg)?));
            }
        }
        for (index, value) in values.iter().enumerate() {
            let rd = index as u8;
            match value {
                RegOrImm::Reg(name) => {
                    let rs = parse_x(name)?;
                    if rs != rd {
                        self.code.put(0xAA00_03E0 | ((rs as u32) << 16) | rd as u32);
                    }
                }
                RegOrImm::Imm(imm) => self.code.abs_addr(rd, *imm),
            }
        }
        let scratch = values.len() as u8;
        self.code.abs_addr(scratch, target);
        self.code.blr(scratch);
        Ok(())
    }
}

enum RegOrImm {
    Reg(String),
    Imm(u64),
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
        return Ok((true, n));
    }
    if let Some(rest) = name.strip_prefix('w') {
        let n: u8 = rest.parse().map_err(|_| js_err("bad register"))?;
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

fn map_err(error: runtime::Error) -> rquickjs::Error {
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
                        let word = u32::from_le_bytes(bytes.try_into().unwrap());
                        last_r.set((word, pc));
                        cursor_r.set(pc + 4);
                        let insn = gum::arch::classify(word);
                        if insn.is_branch() && !matches!(insn, gum::arch::Insn::Bl { .. }) {
                            eoi_r.set(true);
                            reloc_r.set("eoi", true)?;
                        }
                        let decoded = gum::arch::decode(word, pc as u64);
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
