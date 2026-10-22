//! Runtime C compiler for `CModule`, backed by TinyCC.
//!
//! `new CModule(source[, symbols[, options]])` compiles `source`, links it in
//! memory, and exposes each global as a `NativePointer`. Undefined symbols are
//! taken from `symbols` first, then from the process (`malloc`, `strlen`, …).
//! `dispose()` frees the module. `#include <stdint.h>` and `<string.h>` use the
//! small headers staged next to `libtcc1.a`.

use std::cell::RefCell;
use std::collections::HashMap;
use std::ffi::{CStr, CString};
use std::fs;
use std::os::raw::{c_char, c_int, c_void};
use std::path::PathBuf;
use std::ptr;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Mutex;

use rquickjs::{Ctx, Function, Object, Result as JsResult, Value};

use crate::api::{js_error, parse_pointer, to_js_error, NativePointer};

const TCC_OUTPUT_MEMORY: c_int = 1;

#[repr(C)]
struct TccState {
    _private: [u8; 0],
}

unsafe extern "C" {
    fn tcc_new() -> *mut TccState;
    fn tcc_delete(state: *mut TccState);
    fn tcc_set_error_func(
        state: *mut TccState,
        opaque: *mut c_void,
        func: Option<unsafe extern "C" fn(*mut c_void, *const c_char)>,
    );
    fn tcc_set_lib_path(state: *mut TccState, path: *const c_char);
    fn tcc_add_sysinclude_path(state: *mut TccState, path: *const c_char) -> c_int;
    fn tcc_set_options(state: *mut TccState, options: *const c_char);
    fn tcc_set_output_type(state: *mut TccState, output_type: c_int) -> c_int;
    fn tcc_compile_string(state: *mut TccState, buf: *const c_char) -> c_int;
    fn tcc_add_symbol(state: *mut TccState, name: *const c_char, val: *const c_void) -> c_int;
    fn tcc_relocate(state: *mut TccState) -> c_int;
    fn tcc_get_symbol(state: *mut TccState, name: *const c_char) -> *mut c_void;
    fn tcc_list_symbols(
        state: *mut TccState,
        ctx: *mut c_void,
        cb: Option<unsafe extern "C" fn(*mut c_void, *const c_char, *const c_void)>,
    );
}

const LIBTCC1: &[u8] = include_bytes!(env!("CA_LIBTCC1"));

const HEADERS: &[(&str, &str)] = &[
    (
        "stddef.h",
        r#"
#pragma once
typedef unsigned long size_t;
typedef long ptrdiff_t;
#define NULL ((void*)0)
"#,
    ),
    (
        "stdint.h",
        r#"
#pragma once
typedef signed char int8_t;
typedef short int16_t;
typedef int int32_t;
typedef long long int64_t;
typedef unsigned char uint8_t;
typedef unsigned short uint16_t;
typedef unsigned int uint32_t;
typedef unsigned long long uint64_t;
typedef unsigned long uintptr_t;
typedef long intptr_t;
"#,
    ),
    (
        "stdbool.h",
        r#"
#pragma once
#define bool _Bool
#define true 1
#define false 0
"#,
    ),
    (
        "string.h",
        r#"
#pragma once
#include <stddef.h>
void *memcpy(void *dst, const void *src, size_t n);
void *memmove(void *dst, const void *src, size_t n);
void *memset(void *dst, int c, size_t n);
int memcmp(const void *a, const void *b, size_t n);
size_t strlen(const char *s);
int strcmp(const char *a, const char *b);
int strncmp(const char *a, const char *b, size_t n);
char *strcpy(char *dst, const char *src);
char *strncpy(char *dst, const char *src, size_t n);
"#,
    ),
    (
        "stdlib.h",
        r#"
#pragma once
#include <stddef.h>
void *malloc(size_t size);
void *calloc(size_t n, size_t size);
void *realloc(void *ptr, size_t size);
void free(void *ptr);
void abort(void);
void exit(int status);
"#,
    ),
    (
        "stdio.h",
        r#"
#pragma once
#include <stddef.h>
int printf(const char *fmt, ...);
int snprintf(char *buf, size_t n, const char *fmt, ...);
int puts(const char *s);
"#,
    ),
];

const BUILTIN_SYMBOLS: &[&str] = &[
    "malloc",
    "calloc",
    "realloc",
    "free",
    "memcpy",
    "memmove",
    "memset",
    "memcmp",
    "strlen",
    "strcmp",
    "strncmp",
    "strcpy",
    "strncpy",
    "printf",
    "snprintf",
    "puts",
    "abort",
    "exit",
];

thread_local! {
    static ERRORS: RefCell<String> = const { RefCell::new(String::new()) };
}

struct StatePtr(*mut TccState);
// TinyCC state is only touched on the script thread, then freed by `dispose`.
unsafe impl Send for StatePtr {}

static MODULES: Mutex<Option<HashMap<u64, StatePtr>>> = Mutex::new(None);
static NEXT_ID: AtomicU64 = AtomicU64::new(1);

unsafe extern "C" fn on_error(_opaque: *mut c_void, message: *const c_char) {
    if message.is_null() {
        return;
    }
    // SAFETY: TinyCC passes a NUL-terminated diagnostic.
    let text = unsafe { CStr::from_ptr(message) }.to_string_lossy();
    ERRORS.with(|errors| {
        let mut errors = errors.borrow_mut();
        if !errors.is_empty() {
            errors.push('\n');
        }
        errors.push_str(text.trim());
    });
}

struct Compiled {
    id: u64,
    symbols: Vec<(String, u64)>,
}

pub fn compile<'js>(
    ctx: Ctx<'js>,
    source: String,
    symbols: Option<Object<'js>>,
    _options: Option<Object<'js>>,
) -> JsResult<Object<'js>> {
    let compiled = compile_source(&source, &symbol_map(&symbols)?).map_err(js_error)?;
    let object = Object::new(ctx.clone())?;
    object.set("__id", compiled.id)?;
    for (name, address) in &compiled.symbols {
        if !is_public_symbol(name) {
            continue;
        }
        object.set(name.as_str(), NativePointer::instance(ctx.clone(), *address)?)?;
    }
    let id = compiled.id;
    object.set(
        "dispose",
        Function::new(ctx, move || {
            dispose(id);
        })?,
    )?;
    Ok(object)
}

pub fn builtins_headers() -> &'static [(&'static str, &'static str)] {
    HEADERS
}

fn compile_source(source: &str, symbols: &HashMap<String, u64>) -> Result<Compiled, String> {
    let runtime = stage_runtime().map_err(|err| err.to_string())?;
    ERRORS.with(|errors| errors.borrow_mut().clear());
    // SAFETY: TinyCC's state API is used in the order its header requires.
    // The state stays alive until `dispose` so the generated code remains mapped.
    unsafe {
        let state = tcc_new();
        if state.is_null() {
            return Err("tcc_new failed".into());
        }
        tcc_set_error_func(state, ptr::null_mut(), Some(on_error));
        let lib = CString::new(runtime.lib.display().to_string()).map_err(|err| err.to_string())?;
        let include = CString::new(runtime.include.display().to_string()).map_err(|err| err.to_string())?;
        tcc_set_lib_path(state, lib.as_ptr());
        tcc_add_sysinclude_path(state, include.as_ptr());
        let options = CString::new("-nostdinc -nostdlib -Wall").unwrap();
        tcc_set_options(state, options.as_ptr());
        if tcc_set_output_type(state, TCC_OUTPUT_MEMORY) != 0 {
            let message = take_errors();
            tcc_delete(state);
            return Err(format!("tcc_set_output_type: {message}"));
        }
        let prefixed = format!("#line 1 \"module.c\"\n{source}");
        let code = CString::new(prefixed).map_err(|_| "C source contains an interior NUL".to_string())?;
        if tcc_compile_string(state, code.as_ptr()) != 0 {
            let message = take_errors();
            tcc_delete(state);
            return Err(format!("Compilation failed: {message}"));
        }
        add_symbols(state, symbols)?;
        if tcc_relocate(state) != 0 {
            let message = take_errors();
            tcc_delete(state);
            return Err(format!("Link failed: {message}"));
        }
        let listed = list_symbols(state);
        let id = NEXT_ID.fetch_add(1, Ordering::Relaxed);
        let mut modules = MODULES.lock().unwrap_or_else(|err| err.into_inner());
        modules
            .get_or_insert_with(HashMap::new)
            .insert(id, StatePtr(state));
        Ok(Compiled { id, symbols: listed })
    }
}

fn add_symbols(state: *mut TccState, symbols: &HashMap<String, u64>) -> Result<(), String> {
    let mut bound = HashMap::new();
    for name in BUILTIN_SYMBOLS {
        if let Some(address) = runtime::dlsym::resolve(name) {
            bound.insert((*name).to_owned(), address as u64);
        }
    }
    for (name, address) in symbols {
        bound.insert(name.clone(), *address);
    }
    for (name, address) in bound {
        if address == 0 {
            continue;
        }
        let c_name = CString::new(name).map_err(|_| "symbol name contains NUL".to_string())?;
        // SAFETY: `address` is a resolved function or data pointer supplied by
        // the caller or by `dlsym`. TinyCC stores the pointer, it does not free it.
        unsafe { tcc_add_symbol(state, c_name.as_ptr(), address as *const c_void) };
    }
    Ok(())
}

fn list_symbols(state: *mut TccState) -> Vec<(String, u64)> {
    let mut out = Vec::new();
    // SAFETY: `out` stays valid for the callback. TinyCC names are NUL-terminated.
    unsafe {
        tcc_list_symbols(
            state,
            (&mut out as *mut Vec<(String, u64)>).cast(),
            Some(on_symbol),
        );
    }
    out
}

unsafe extern "C" fn on_symbol(ctx: *mut c_void, name: *const c_char, value: *const c_void) {
    if name.is_null() || value.is_null() {
        return;
    }
    // SAFETY: caller passes the Vec allocated in `list_symbols`.
    let out = unsafe { &mut *ctx.cast::<Vec<(String, u64)>>() };
    let name = unsafe { CStr::from_ptr(name) }.to_string_lossy().into_owned();
    out.push((name, value as u64));
}

fn is_public_symbol(name: &str) -> bool {
    let name = name.trim_start_matches('_');
    !name.is_empty()
        && name
            .chars()
            .next()
            .is_some_and(|c| c == '_' || c.is_ascii_alphabetic())
        && name.chars().all(|c| c == '_' || c.is_ascii_alphanumeric())
}

fn dispose(id: u64) {
    let Some(StatePtr(state)) = MODULES
        .lock()
        .unwrap_or_else(|err| err.into_inner())
        .as_mut()
        .and_then(|modules| modules.remove(&id))
    else {
        return;
    };
    // SAFETY: `state` was created by `tcc_new` and has not been deleted.
    unsafe { tcc_delete(state) };
}

fn take_errors() -> String {
    ERRORS.with(|errors| {
        let text = errors.borrow().clone();
        if text.is_empty() {
            "unknown TinyCC error".into()
        } else {
            text
        }
    })
}

struct RuntimePaths {
    lib: PathBuf,
    include: PathBuf,
}

fn stage_runtime() -> std::io::Result<RuntimePaths> {
    static READY: Mutex<Option<RuntimePaths>> = Mutex::new(None);
    let mut slot = READY.lock().unwrap_or_else(|err| err.into_inner());
    if let Some(paths) = slot.as_ref() {
        return Ok(paths.clone());
    }
    let root = runtime_root()?;
    let include = root.join("include");
    fs::create_dir_all(&include)?;
    fs::write(root.join("libtcc1.a"), LIBTCC1)?;
    for (name, body) in HEADERS {
        fs::write(include.join(name), body)?;
    }
    let paths = RuntimePaths {
        lib: root.clone(),
        include,
    };
    *slot = Some(paths.clone());
    Ok(paths)
}

impl Clone for RuntimePaths {
    fn clone(&self) -> Self {
        Self {
            lib: self.lib.clone(),
            include: self.include.clone(),
        }
    }
}

fn runtime_root() -> std::io::Result<PathBuf> {
    let mut candidates = vec![
        std::env::temp_dir().join("ca-tcc"),
        PathBuf::from("/data/local/tmp/ca-tcc"),
    ];
    if let Ok(bytes) = fs::read("/proc/self/cmdline") {
        let name = String::from_utf8_lossy(&bytes);
        let name = name.split('\0').next().unwrap_or("");
        if name.contains('.') {
            candidates.push(PathBuf::from(format!("/data/user/0/{name}/cache/ca-tcc")));
            candidates.push(PathBuf::from(format!(
                "/data/user_de/0/{name}/cache/ca-tcc"
            )));
        }
    }
    let mut last = std::io::Error::other("no writable TinyCC directory");
    for candidate in candidates {
        match fs::create_dir_all(&candidate) {
            Ok(()) => return Ok(candidate),
            Err(err) => last = err,
        }
    }
    Err(last)
}

fn symbol_map(symbols: &Option<Object<'_>>) -> JsResult<HashMap<String, u64>> {
    let mut out = HashMap::new();
    let Some(symbols) = symbols else {
        return Ok(out);
    };
    for key in symbols.keys::<String>() {
        let key = key.map_err(|err| to_js_error(err.to_string()))?;
        let value: Value = symbols.get(&key).map_err(|err| to_js_error(err.to_string()))?;
        out.insert(key, parse_pointer(&value)?);
    }
    Ok(out)
}

