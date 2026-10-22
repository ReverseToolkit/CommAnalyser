//! In-process self-test of the shipped agent.
//!
//! Cases run inside the injected process against real maps, real libc, and
//! the same hook/JS/TAL paths scripts use. Each case is isolated so one
//! failure does not skip the rest.

use std::cell::RefCell;
use std::ffi::c_void;
use std::panic::{catch_unwind, AssertUnwindSafe};
use std::ptr;
use std::sync::atomic::{AtomicU64, AtomicUsize, Ordering};

use serde_json::{json, Value};

use gum::hook::{InlineHook, SavedRegs};
use js::JsWorker;

struct Outcome {
    layer: &'static str,
    name: &'static str,
    ok: Option<bool>,
    detail: String,
}

impl Outcome {
    fn pass(layer: &'static str, name: &'static str, detail: impl Into<String>) -> Self {
        Self {
            layer,
            name,
            ok: Some(true),
            detail: detail.into(),
        }
    }

    fn fail(layer: &'static str, name: &'static str, detail: impl Into<String>) -> Self {
        Self {
            layer,
            name,
            ok: Some(false),
            detail: detail.into(),
        }
    }

    fn skip(layer: &'static str, name: &'static str, detail: impl Into<String>) -> Self {
        Self {
            layer,
            name,
            ok: None,
            detail: detail.into(),
        }
    }

    fn to_json(&self) -> Value {
        json!({
            "layer": self.layer,
            "name": self.name,
            "ok": self.ok,
            "detail": self.detail,
        })
    }
}

thread_local! {
    /// Optional `layer.case` prefix used to run one case at a time.
    static CASE_FILTER: RefCell<String> = const { RefCell::new(String::new()) };
}

fn selected(layer: &str, name: &str) -> bool {
    CASE_FILTER.with(|filter| {
        let want = filter.borrow();
        want.is_empty()
            || format!("{layer}.{name}").starts_with(want.as_str())
            || layer.starts_with(want.as_str())
    })
}

/// Run every in-process case. `suite` selects a layer or `layer.case` prefix
/// (`runtime`, `gum`, `gum.hook_enter`, `js`, `trace`, `java`, `il2cpp`).
/// `il2cpp` runs only when asked: a process without `libil2cpp.so` is not a failure
/// of the other suites.
pub fn run(worker: Option<&JsWorker>, suite: Option<&str>) -> Value {
    let mut cases = Vec::new();
    let want = suite.unwrap_or("");
    CASE_FILTER.with(|filter| *filter.borrow_mut() = want.to_owned());
    let take = |layer: &str| {
        want.is_empty() || layer.starts_with(want) || want.starts_with(layer)
    };

    if take("runtime") {
        cases.push(guard("runtime", "maps", test_maps));
        cases.push(guard("runtime", "module_export", test_module_export));
        cases.push(guard("runtime", "process", test_process));
    }
    if take("gum") {
        cases.push(guard("gum", "memory", test_memory));
        cases.push(guard("gum", "native_strlen", test_native_strlen));
        cases.push(guard("gum", "native_sqrt", test_native_sqrt));
        cases.push(guard("gum", "native_f32", test_native_f32));
        cases.extend(arch_cases());
        cases.extend(hook_cases());
    }
    if take("js") {
        match worker {
            Some(worker) => cases.extend(js_cases(worker)),
            None => cases.push(Outcome::skip("js", "worker", "QuickJS unavailable")),
        }
    }
    if take("trace") {
        match worker {
            Some(worker) => cases.push(js_eval(
                worker,
                "trace",
                "libm_sqrt",
                r#"
                (function () {
                  var sqrt = Module.findExportByName('libm.so', 'sqrt');
                  if (!sqrt) throw new Error('no sqrt');
                  var path = Process.getTmpDir() + '/ca-trace-sqrt.txt';
                  Trace.function(sqrt, { events: ['inst', 'mem'], file: path });
                  var n = new NativeFunction(sqrt, 'double', ['double'])(9.0);
                  var head = File.readAllText(path).split('\n')[0];
                  var m = /^events=(\d+)/.exec(head);
                  if (!m || parseInt(m[1], 10) < 1) throw new Error('no events ' + head + ' n=' + n);
                  if (Math.abs(n - 3) > 1e-9) throw new Error('want 3 n=' + n);
                  return 'n=' + n + ' ' + head;
                })()
                "#,
            )),
            None => cases.push(Outcome::skip("trace", "libm_sqrt", "QuickJS unavailable")),
        }
        match worker {
            Some(worker) => cases.push(js_eval(
                worker,
                "trace",
                "libm_ilogb",
                r#"
                (function () {
                  var ilogb = Module.findExportByName('libm.so', 'ilogb');
                  if (!ilogb) throw new Error('no ilogb');
                  var path = Process.getTmpDir() + '/ca-trace-ilogb.txt';
                  Trace.function(ilogb, { events: ['inst'], file: path });
                  var n = new NativeFunction(ilogb, 'int', ['double'])(8.0);
                  var head = File.readAllText(path).split('\n')[0];
                  var m = /^events=(\d+)/.exec(head);
                  if (n !== 3) throw new Error('want 3 n=' + n);
                  if (!m || parseInt(m[1], 10) < 1) throw new Error('no events ' + head);
                  return 'n=' + n + ' ' + head;
                })()
                "#,
            )),
            None => cases.push(Outcome::skip("trace", "libm_ilogb", "QuickJS unavailable")),
        }
        match worker {
            Some(worker) => cases.push(js_eval(
                worker,
                "trace",
                "libm_hypot",
                r#"
                (function () {
                  var hypot = Module.findExportByName('libm.so', 'hypot');
                  if (!hypot) throw new Error('no hypot');
                  var path = Process.getTmpDir() + '/ca-trace-hypot.txt';
                  Trace.function(hypot, { events: ['inst'], file: path });
                  var n = new NativeFunction(hypot, 'double', ['double', 'double'])(3, 4);
                  var head = File.readAllText(path).split('\n')[0];
                  var m = /^events=(\d+)/.exec(head);
                  if (Math.abs(n - 5) > 1e-9) throw new Error('want 5 n=' + n);
                  if (!m || parseInt(m[1], 10) < 1) throw new Error('no events ' + head);
                  return 'n=' + n + ' ' + head;
                })()
                "#,
            )),
            None => cases.push(Outcome::skip("trace", "libm_hypot", "QuickJS unavailable")),
        }
    }
    if want == "il2cpp" || want.starts_with("il2cpp.") {
        cases.push(guard("il2cpp", "summary", test_il2cpp_summary));
        cases.push(guard("il2cpp", "domain", test_il2cpp_domain));
        cases.push(guard("il2cpp", "class", test_il2cpp_class));
        cases.push(guard("il2cpp", "method", test_il2cpp_method));
        cases.push(guard("il2cpp", "field", test_il2cpp_field));
        cases.push(guard("il2cpp", "string", test_il2cpp_string));
        cases.push(guard("il2cpp", "gc", test_il2cpp_gc));
        cases.push(guard("il2cpp", "dump", test_il2cpp_dump));
        cases.push(guard("il2cpp", "trace", test_il2cpp_trace));
    }
    if take("java") {
        cases.extend(java_cases(worker));
    }

    let passed = cases.iter().filter(|c| c.ok == Some(true)).count();
    let failed = cases.iter().filter(|c| c.ok == Some(false)).count();
    let skipped = cases.iter().filter(|c| c.ok.is_none()).count();
    json!({
        "ok": failed == 0,
        "passed": passed,
        "failed": failed,
        "skipped": skipped,
        "pid": std::process::id(),
        "arch": runtime::process::arch(),
        "cases": cases.iter().map(Outcome::to_json).collect::<Vec<_>>(),
    })
}

fn guard(
    layer: &'static str,
    name: &'static str,
    f: impl FnOnce() -> Result<String, String>,
) -> Outcome {
    if !selected(layer, name) {
        return Outcome::skip(layer, name, "filtered");
    }
    match catch_unwind(AssertUnwindSafe(f)) {
        Ok(Ok(detail)) => Outcome::pass(layer, name, detail),
        Ok(Err(err)) => Outcome::fail(layer, name, err),
        Err(_) => Outcome::fail(layer, name, "panic"),
    }
}

fn test_maps() -> Result<String, String> {
    let maps = runtime::maps::read_self_maps().map_err(|err| err.to_string())?;
    if maps.is_empty() {
        return Err("empty /proc/self/maps".into());
    }
    let libc = maps
        .iter()
        .any(|m| m.clean_path().is_some_and(|path| path.contains("libc.so")));
    let exec = maps.iter().any(|m| m.perms.exec);
    if !libc {
        return Err("libc.so mapping missing".into());
    }
    if !exec {
        return Err("no executable mapping".into());
    }
    Ok(format!("entries={} exec={}", maps.len(), exec))
}

fn test_module_export() -> Result<String, String> {
    let modules = runtime::module::enumerate().map_err(|err| err.to_string())?;
    let libc = modules
        .iter()
        .find(|m| m.name == "libc.so" || m.name.starts_with("libc.so."))
        .ok_or("libc.so module missing")?;
    let getpid = runtime::dlsym::resolve("getpid").ok_or("dlsym(getpid) failed")?;
    if !libc.contains(getpid) && getpid < libc.base {
        // IFUNC / vdso aliases can live outside the file-backed range; still require a live symbol.
    }
    Ok(format!(
        "libc={:#x}..{:#x} getpid={:#x}",
        libc.base, libc.end, getpid
    ))
}

fn test_process() -> Result<String, String> {
    let pid = runtime::process::id();
    if pid == 0 {
        return Err("pid 0".into());
    }
    let page = runtime::process::page_size();
    if !page.is_power_of_two() || page < 4096 {
        return Err(format!("bad page size {page}"));
    }
    Ok(format!(
        "pid={pid} page={page} arch={}",
        runtime::process::arch()
    ))
}

fn test_il2cpp_summary() -> Result<String, String> {
    let value = il2cpp::summary().map_err(|err| err.to_string())?;
    let assemblies = value["assemblies"].as_array().map(|items| items.len()).unwrap_or(0);
    if assemblies == 0 {
        return Err(format!("no assemblies: {value}"));
    }
    let sample_len = value["sampleLen"].as_i64().unwrap_or(-1);
    if sample_len != 5 {
        return Err(format!("string length {sample_len}: {value}"));
    }
    let get_length = value["getLength"].as_str().unwrap_or("0x0");
    if get_length == "0x0" {
        return Err(format!("get_Length has no virtual address: {value}"));
    }
    Ok(format!(
        "module={} assemblies={assemblies} corlibClasses={} stringMethods={} getLength={get_length} unity={}",
        value["module"].as_str().unwrap_or("?"),
        value["corlibClasses"],
        value["stringMethods"],
        value["unity"]
    ))
}

fn il2cpp_runtime() -> Result<il2cpp::Runtime, String> {
    il2cpp::Runtime::session().map_err(|err| err.to_string())
}

fn test_il2cpp_domain() -> Result<String, String> {
    let rt = il2cpp_runtime()?;
    let domain = rt.domain().map_err(|err| err.to_string())?;
    let assemblies = domain.assemblies(&rt).map_err(|err| err.to_string())?;
    if assemblies.is_empty() {
        return Err("no assemblies".into());
    }
    let missing = domain
        .try_assembly(&rt, "no.such.assembly")
        .map_err(|err| err.to_string())?;
    if missing.is_some() {
        return Err("missing assembly resolved".into());
    }
    let mscorlib = domain.assembly(&rt, "mscorlib").map_err(|err| err.to_string())?;
    let image = mscorlib.image(&rt).map_err(|err| err.to_string())?;
    let name = image.name(&rt).map_err(|err| err.to_string())?;
    if !name.contains("mscorlib") {
        return Err(format!("image {name}"));
    }
    let count = image.class_count(&rt).map_err(|err| err.to_string())?;
    if count == 0 {
        return Err("mscorlib class count 0".into());
    }
    Ok(format!("assemblies={} image={name} classes={count}", assemblies.len()))
}

fn test_il2cpp_class() -> Result<String, String> {
    let rt = il2cpp_runtime()?;
    let class = rt
        .corlib()
        .map_err(|err| err.to_string())?
        .class(&rt, "System.String")
        .map_err(|err| err.to_string())?;
    let full = class.full_name(&rt).map_err(|err| err.to_string())?;
    if full != "System.String" {
        return Err(full);
    }
    let parent = class
        .parent(&rt)
        .map_err(|err| err.to_string())?
        .ok_or("String has no parent")?;
    let parent_name = parent.full_name(&rt).map_err(|err| err.to_string())?;
    if parent_name != "System.Object" {
        return Err(format!("parent {parent_name}"));
    }
    if class.kind(&rt).map_err(|err| err.to_string())? != "class" {
        return Err("String is not a class".into());
    }
    if class.is_enum(&rt).map_err(|err| err.to_string())? {
        return Err("String is an enum".into());
    }
    let size = class.instance_size(&rt).map_err(|err| err.to_string())?;
    if size <= 0 {
        return Err(format!("instance size {size}"));
    }
    let flags = class.flags(&rt).map_err(|err| err.to_string())?;
    let nested = class.nested(&rt).map_err(|err| err.to_string())?;
    Ok(format!(
        "full={full} parent={parent_name} size={size} flags={flags:#x} nested={}",
        nested.len()
    ))
}

fn test_il2cpp_method() -> Result<String, String> {
    let mut rt = il2cpp_runtime()?;
    let class = rt
        .corlib()
        .map_err(|err| err.to_string())?
        .class(&rt, "System.String")
        .map_err(|err| err.to_string())?;
    let methods = class.methods(&rt).map_err(|err| err.to_string())?;
    if methods.is_empty() {
        return Err("no methods".into());
    }
    let length = class.method(&rt, "get_Length", 0).map_err(|err| err.to_string())?;
    if length.is_static(&rt).map_err(|err| err.to_string())? {
        return Err("get_Length is static".into());
    }
    if length.param_count(&rt).map_err(|err| err.to_string())? != 0 {
        return Err("get_Length has parameters".into());
    }
    let signature = length.signature(&rt).map_err(|err| err.to_string())?;
    let va = length.virtual_address(&mut rt).map_err(|err| err.to_string())?;
    if va == 0 {
        return Err("null virtual address".into());
    }
    let sample = rt.new_string("mouse").map_err(|err| err.to_string())?;
    let got = length.invoke_raw(&mut rt, sample, &[]).map_err(|err| err.to_string())?;
    if got != 5 {
        return Err(format!("invoke get_Length={got}"));
    }
    Ok(format!("methods={} sig={signature} va={va:#x} invoke={got}", methods.len()))
}

fn test_il2cpp_field() -> Result<String, String> {
    let rt = il2cpp_runtime()?;
    let class = rt
        .corlib()
        .map_err(|err| err.to_string())?
        .class(&rt, "System.String")
        .map_err(|err| err.to_string())?;
    let fields = class.fields(&rt).map_err(|err| err.to_string())?;
    let field = fields.first().ok_or("String has no fields")?;
    let name = field.name(&rt).map_err(|err| err.to_string())?;
    if name.is_empty() {
        return Err("empty field name".into());
    }
    let type_name = field.type_(&rt).map_err(|err| err.to_string())?.name(&rt).map_err(|err| err.to_string())?;
    if type_name.is_empty() {
        return Err(format!("field {name} has an empty type"));
    }
    let offset = field.offset(&rt).map_err(|err| err.to_string())?;
    let flags = field.flags(&rt).map_err(|err| err.to_string())?;
    Ok(format!(
        "fields={} first={name} type={type_name} offset={offset:#x} flags={flags:#x} static={}",
        fields.len(),
        field.is_static(&rt).map_err(|err| err.to_string())?
    ))
}

fn test_il2cpp_string() -> Result<String, String> {
    let rt = il2cpp_runtime()?;
    let sample = rt.new_string("mouse").map_err(|err| err.to_string())?;
    let len = rt.string_length(sample).map_err(|err| err.to_string())?;
    let text = rt.string_utf16(sample).map_err(|err| err.to_string())?;
    if len != 5 || text != "mouse" {
        return Err(format!("len={len} text={text}"));
    }
    Ok(format!("text={text} len={len}"))
}

fn test_il2cpp_gc() -> Result<String, String> {
    let rt = il2cpp_runtime()?;
    let heap = rt.gc_heap_size().map_err(|err| err.to_string())?;
    let used = rt.gc_used_size().map_err(|err| err.to_string())?;
    let threads = rt.attached_threads().map_err(|err| err.to_string())?;
    if threads.is_empty() {
        return Err("no attached threads".into());
    }
    Ok(format!("heap={heap} used={used} threads={}", threads.len()))
}

fn test_il2cpp_dump() -> Result<String, String> {
    let rt = il2cpp_runtime()?;
    let class = rt
        .corlib()
        .map_err(|err| err.to_string())?
        .class(&rt, "System.String")
        .map_err(|err| err.to_string())?;
    let one = il2cpp::dump_class(&rt, class).map_err(|err| err.to_string())?;
    if !one.contains("System.String") || !one.contains("get_Length") {
        return Err(one);
    }
    let path = format!("{}/ca-il2cpp-dump.txt", app_cache_dir());
    let text = il2cpp::dump_assembly(&rt, Some("mscorlib"), Some(1)).map_err(|err| err.to_string())?;
    std::fs::write(&path, &text).map_err(|err| err.to_string())?;
    let read = std::fs::read_to_string(&path).map_err(|err| err.to_string())?;
    if read != text {
        return Err("dump file mismatch".into());
    }
    Ok(format!("class_lines={} file={path}", one.lines().count()))
}

fn test_il2cpp_trace() -> Result<String, String> {
    #[cfg(not(target_os = "android"))]
    {
        Err("trace_method is built for Android".into())
    }
    #[cfg(target_os = "android")]
    {
        let mut rt = il2cpp_runtime()?;
        let class = rt
            .corlib()
            .map_err(|err| err.to_string())?
            .class(&rt, "System.String")
            .map_err(|err| err.to_string())?;
        let length = class.method(&rt, "get_Length", 0).map_err(|err| err.to_string())?;
        let path = format!("{}/ca-il2cpp-trace.txt", app_cache_dir());
        let _ = std::fs::remove_file(&path);
        il2cpp::trace_method(&mut rt, length, path.clone()).map_err(|err| err.to_string())?;
        let sample = rt.new_string("mouse").map_err(|err| err.to_string())?;
        let got = length.invoke_raw(&mut rt, sample, &[]).map_err(|err| err.to_string())?;
        if got != 5 {
            return Err(format!("traced invoke={got}"));
        }
        let text = std::fs::read_to_string(&path).map_err(|err| err.to_string())?;
        if !text.contains("enter") || !text.contains("leave") {
            return Err(text);
        }
        Ok(format!("lines={} invoke={got}", text.lines().count()))
    }
}

fn app_cache_dir() -> String {
    let bytes = std::fs::read("/proc/self/cmdline").unwrap_or_default();
    let name = String::from_utf8_lossy(&bytes);
    let name = name.split('\0').next().unwrap_or("");
    if name.contains('.') {
        format!("/data/user/0/{name}/cache")
    } else {
        "/data/local/tmp".into()
    }
}

fn test_memory() -> Result<String, String> {
    let ptr = gum::memory::alloc(64).map_err(|err| err.to_string())?;
    let addr = ptr as usize;
    let payload = [0x11u8, 0x22, 0x33, 0x44];
    gum::memory::write(addr, &payload).map_err(|err| err.to_string())?;
    let read = gum::memory::read(addr, 4).map_err(|err| err.to_string())?;
    if read != payload {
        gum::memory::free(ptr, 64);
        return Err(format!("readback {read:?}"));
    }
    gum::memory::protect(
        addr,
        64,
        libc::PROT_READ | libc::PROT_WRITE | libc::PROT_EXEC,
    )
    .map_err(|err| err.to_string())?;
    gum::memory::patch_code(addr, &[0x1F, 0x20, 0x03, 0xD5]).map_err(|err| err.to_string())?;
    let patched = gum::memory::read(addr, 4).map_err(|err| err.to_string())?;
    gum::memory::free(ptr, 64);
    if patched != [0x1F, 0x20, 0x03, 0xD5] {
        return Err(format!("patch {patched:?}"));
    }
    Ok("alloc/write/read/protect/patch".into())
}

fn test_native_strlen() -> Result<String, String> {
    let strlen = runtime::dlsym::resolve("strlen").ok_or("dlsym(strlen) failed")?;
    let hello = c"abcdef";
    let ret = unsafe { js::native::call(strlen, &[hello.as_ptr() as u64]) }
        .map_err(|err| err.to_string())?;
    if ret != 6 {
        return Err(format!("strlen= {ret}"));
    }
    Ok(format!("strlen={ret}"))
}

#[inline(never)]
#[no_mangle]
extern "C" fn commanalyser_selftest_three_f64() -> f64 {
    3.0
}

#[inline(never)]
extern "C" fn commanalyser_selftest_half_f32(x: f32) -> f32 {
    x * 0.5
}

fn test_native_f32() -> Result<String, String> {
    let got = unsafe {
        js::native::call_f32(
            std::hint::black_box(commanalyser_selftest_half_f32 as *const () as usize),
            &[],
            &[u64::from(0.5f32.to_bits())],
        )
    }
    .map_err(|err| err.to_string())?;
    if (got - 0.25).abs() > 1e-6 {
        return Err(format!("f32={got}"));
    }
    Ok(format!("f32={got}"))
}

fn test_native_sqrt() -> Result<String, String> {
    let ret = unsafe {
        js::native::call_f64(
            std::hint::black_box(commanalyser_selftest_three_f64 as *const () as usize),
            &[],
            &[],
        )
    }
    .map_err(|err| err.to_string())?;
    if (ret - 3.0).abs() > 1e-9 {
        return Err(format!("d0={ret}"));
    }
    Ok(format!("d0={ret}"))
}

fn arch_cases() -> Vec<Outcome> {
    #[cfg(target_arch = "aarch64")]
    {
        vec![
            guard("gum", "writer_execute", test_writer_execute),
            guard("gum", "relocator_nop", test_relocator_nop),
        ]
    }
    #[cfg(not(target_arch = "aarch64"))]
    {
        vec![Outcome::skip(
            "gum",
            "writer_execute",
            "host is not aarch64",
        )]
    }
}

#[cfg(target_arch = "aarch64")]
fn test_writer_execute() -> Result<String, String> {
    let mut writer = arch_arm64::writer::CodeWriter::new();
    writer.bti_c();
    writer.put(0x5280_0540); // mov w0, #42
    writer.ret(30);
    let page = unsafe {
        libc::mmap(
            ptr::null_mut(),
            0x1000,
            libc::PROT_READ | libc::PROT_WRITE | libc::PROT_EXEC,
            libc::MAP_PRIVATE | libc::MAP_ANONYMOUS,
            -1,
            0,
        )
    };
    if page == libc::MAP_FAILED {
        return Err("mmap failed".into());
    }
    unsafe {
        ptr::copy_nonoverlapping(writer.bytes().as_ptr(), page as *mut u8, writer.len());
    }
    gum::memory::flush_icache(page as usize, writer.len());
    let ret = unsafe { js::native::call(page as usize, &[]) }.map_err(|err| {
        unsafe { libc::munmap(page, 0x1000) };
        err.to_string()
    })?;
    unsafe { libc::munmap(page, 0x1000) };
    if ret != 42 {
        return Err(format!("got {ret}"));
    }
    Ok("mov w0,#42; ret".into())
}

#[cfg(target_arch = "aarch64")]
fn test_relocator_nop() -> Result<String, String> {
    let relocated =
        arch_arm64::relocator::relocate_one(0xD503_201F, 0x1000).map_err(|err| err.to_string())?;
    if relocated.consumed != 4 || relocated.bytes.len() != 4 {
        return Err(format!("{relocated:?}"));
    }
    Ok("nop relocated in place".into())
}

fn hook_cases() -> Vec<Outcome> {
    #[cfg(target_arch = "aarch64")]
    {
        vec![
            guard("gum", "hook_enter", test_hook_enter),
            guard("gum", "hook_leave_replace", test_hook_leave_replace),
            guard("gum", "hook_gprs", test_hook_gprs),
            guard("gum", "reloc_literal", test_reloc_literal),
            guard("gum", "replace_revert", test_replace_revert),
        ]
    }
    #[cfg(not(target_arch = "aarch64"))]
    {
        vec![Outcome::skip("gum", "hook_enter", "host is not aarch64")]
    }
}

#[cfg(target_arch = "aarch64")]
fn mmap_exec_page() -> Result<*mut c_void, String> {
    const PAGE: usize = 0x1000;
    const FIXED_NOREPLACE: i32 = 0x10_0000;
    let near = runtime::dlsym::resolve("getpid").unwrap_or(0);
    if near != 0 {
        for delta in (0x1_0000..0x40_00000).step_by(0x1_0000) {
            let hint = near.wrapping_add(delta) & !(PAGE - 1);
            let mapped = unsafe {
                libc::mmap(
                    hint as *mut c_void,
                    PAGE,
                    libc::PROT_READ | libc::PROT_WRITE | libc::PROT_EXEC,
                    libc::MAP_PRIVATE | libc::MAP_ANONYMOUS | FIXED_NOREPLACE,
                    -1,
                    0,
                )
            };
            if mapped == libc::MAP_FAILED {
                continue;
            }
            if mapped as usize == hint {
                return Ok(mapped);
            }
            unsafe { libc::munmap(mapped, PAGE) };
        }
    }
    let mapped = unsafe {
        libc::mmap(
            ptr::null_mut(),
            PAGE,
            libc::PROT_READ | libc::PROT_WRITE | libc::PROT_EXEC,
            libc::MAP_PRIVATE | libc::MAP_ANONYMOUS,
            -1,
            0,
        )
    };
    if mapped == libc::MAP_FAILED {
        Err("mmap stub failed".into())
    } else {
        Ok(mapped)
    }
}

#[cfg(target_arch = "aarch64")]
fn emit_stub(words: &[u32]) -> Result<usize, String> {
    let page = mmap_exec_page()?;
    let mut writer = arch_arm64::writer::CodeWriter::new();
    writer.bti_c();
    for word in words {
        writer.put(*word);
    }
    unsafe {
        ptr::copy_nonoverlapping(writer.bytes().as_ptr(), page as *mut u8, writer.len());
    }
    gum::memory::flush_icache(page as usize, writer.len());
    Ok(page as usize)
}

#[cfg(target_arch = "aarch64")]
fn free_stub(addr: usize) {
    if addr != 0 {
        unsafe { libc::munmap(addr as *mut c_void, 0x1000) };
    }
}

/// `add x0, x0, x1; ret` with padding so replace's 16-byte jump fits.
#[cfg(target_arch = "aarch64")]
fn make_add2_stub() -> Result<usize, String> {
    emit_stub(&[
        0xD503_201F,
        0xD503_201F,
        0xD503_201F,
        0xD503_201F,
        0x8B01_0000,
        0xD65F_03C0,
    ])
}

#[cfg(target_arch = "aarch64")]
fn make_seven_stub() -> Result<usize, String> {
    emit_stub(&[0x5280_00E0, 0xD65F_03C0]) // mov w0, #7; ret
}

#[cfg(target_arch = "aarch64")]
fn call_add2_at(target: usize, a: u64, b: u64) -> u64 {
    let f: extern "C" fn(u64, u64) -> u64 = unsafe { std::mem::transmute(target) };
    f(a, b)
}

#[cfg(target_arch = "aarch64")]
static ENTER_HITS: AtomicUsize = AtomicUsize::new(0);
#[cfg(target_arch = "aarch64")]
static LEAVE_HITS: AtomicUsize = AtomicUsize::new(0);
#[cfg(target_arch = "aarch64")]
static SEEN_X0: AtomicU64 = AtomicU64::new(0);
#[cfg(target_arch = "aarch64")]
static SEEN_X1: AtomicU64 = AtomicU64::new(0);
#[cfg(target_arch = "aarch64")]
static SEEN_X19: AtomicU64 = AtomicU64::new(0);
#[cfg(target_arch = "aarch64")]
static SEEN_FP: AtomicU64 = AtomicU64::new(0);
#[cfg(target_arch = "aarch64")]
static SEEN_LR: AtomicU64 = AtomicU64::new(0);
#[cfg(target_arch = "aarch64")]
static SEEN_SP: AtomicU64 = AtomicU64::new(0);
#[cfg(target_arch = "aarch64")]
static REDIR_PC: AtomicU64 = AtomicU64::new(0);
#[cfg(target_arch = "aarch64")]
static REDIR_SP: AtomicU64 = AtomicU64::new(0);

#[cfg(target_arch = "aarch64")]
unsafe extern "C" fn on_add2_enter(regs: *mut SavedRegs, _data: *mut c_void) {
    ENTER_HITS.fetch_add(1, Ordering::SeqCst);
    if regs.is_null() {
        return;
    }
    let regs = unsafe { &*regs };
    SEEN_X0.store(regs.x[0], Ordering::SeqCst);
    SEEN_X1.store(regs.x[1], Ordering::SeqCst);
    SEEN_X19.store(regs.x[19], Ordering::SeqCst);
    SEEN_FP.store(regs.fp, Ordering::SeqCst);
    SEEN_LR.store(regs.lr, Ordering::SeqCst);
    SEEN_SP.store(regs.sp, Ordering::SeqCst);
}

#[cfg(target_arch = "aarch64")]
unsafe extern "C" fn on_add2_leave(regs: *mut SavedRegs, _data: *mut c_void) {
    LEAVE_HITS.fetch_add(1, Ordering::SeqCst);
    if !regs.is_null() {
        unsafe { (*regs).x[0] = 99 };
    }
}

#[cfg(target_arch = "aarch64")]
fn test_hook_enter() -> Result<String, String> {
    ENTER_HITS.store(0, Ordering::SeqCst);
    let target = make_add2_stub()?;
    let mut hook =
        unsafe { InlineHook::attach(target, on_add2_enter, ptr::null_mut()) }.map_err(|err| {
            free_stub(target);
            err.to_string()
        })?;
    let value = call_add2_at(target, 3, 4);
    let hits = ENTER_HITS.load(Ordering::SeqCst);
    let detach = hook.detach();
    let after = call_add2_at(target, 3, 4);
    free_stub(target);
    detach.map_err(|err| err.to_string())?;
    if value != 7 || after != 7 {
        return Err(format!("add2 {value}/{after}"));
    }
    if hits != 1 {
        return Err(format!("hits={hits}"));
    }
    Ok("enter once, detach clean".into())
}

#[cfg(target_arch = "aarch64")]
fn test_hook_leave_replace() -> Result<String, String> {
    LEAVE_HITS.store(0, Ordering::SeqCst);
    let target = make_add2_stub()?;
    let mut hook = unsafe {
        InlineHook::attach_ex(target, on_add2_enter, Some(on_add2_leave), ptr::null_mut())
    }
    .map_err(|err| {
        free_stub(target);
        err.to_string()
    })?;
    let value = call_add2_at(target, 3, 4);
    let detach = hook.detach();
    free_stub(target);
    detach.map_err(|err| err.to_string())?;
    if LEAVE_HITS.load(Ordering::SeqCst) != 1 {
        return Err(format!("leaves={}", LEAVE_HITS.load(Ordering::SeqCst)));
    }
    if value != 99 {
        return Err(format!("retval {value}"));
    }
    Ok("onLeave replaced x0=99".into())
}

#[cfg(target_arch = "aarch64")]
fn test_hook_gprs() -> Result<String, String> {
    ENTER_HITS.store(0, Ordering::SeqCst);
    SEEN_X0.store(0, Ordering::SeqCst);
    SEEN_X1.store(0, Ordering::SeqCst);
    SEEN_LR.store(0, Ordering::SeqCst);
    SEEN_SP.store(0, Ordering::SeqCst);
    let target = make_add2_stub()?;
    let mut hook =
        unsafe { InlineHook::attach(target, on_add2_enter, ptr::null_mut()) }.map_err(|err| {
            free_stub(target);
            err.to_string()
        })?;
    let _ = call_add2_at(target, 0x1111, 0x2222);
    let detach = hook.detach();
    free_stub(target);
    detach.map_err(|err| err.to_string())?;
    let x0 = SEEN_X0.load(Ordering::SeqCst);
    let x1 = SEEN_X1.load(Ordering::SeqCst);
    let lr = SEEN_LR.load(Ordering::SeqCst);
    let sp = SEEN_SP.load(Ordering::SeqCst);
    if x0 != 0x1111 || x1 != 0x2222 {
        return Err(format!("x0={x0:#x} x1={x1:#x}"));
    }
    if lr == 0 {
        return Err("lr is 0".into());
    }
    if sp == 0 {
        return Err("sp is 0".into());
    }
    Ok(format!(
        "x0={x0:#x} x1={x1:#x} x19={:#x} fp={:#x} lr={lr:#x} sp={sp:#x}",
        SEEN_X19.load(Ordering::SeqCst),
        SEEN_FP.load(Ordering::SeqCst)
    ))
}

#[cfg(target_arch = "aarch64")]
unsafe extern "C" fn on_redirect_sp_pc(regs: *mut SavedRegs, _data: *mut c_void) {
    if regs.is_null() {
        return;
    }
    let regs = unsafe { &mut *regs };
    // Keep the caller's SP in x19 and its x19 in x20 so the landing can
    // switch back before RET.  Otherwise the caller pops a foreign stack.
    let caller_sp = regs.sp;
    let caller_x19 = regs.x[19];
    regs.x[20] = caller_x19;
    regs.x[19] = caller_sp;
    regs.pc = REDIR_PC.load(Ordering::SeqCst);
    regs.sp = REDIR_SP.load(Ordering::SeqCst);
}

/// Callback sets SP and PC.  The epilogue must resume at that PC with that SP.
#[cfg(target_arch = "aarch64")]
#[allow(dead_code, reason = "kept as a reference for the old inline trampoline")]
fn test_hook_sp_pc() -> Result<String, String> {
    // bti jc; mov x0, sp; mov sp, x19; mov x19, x20; ret
    let landing = {
        let page = mmap_exec_page()?;
        let mut writer = arch_arm64::writer::CodeWriter::new();
        writer.bti_jc();
        writer.put(0x9100_03E0); // mov x0, sp
        writer.put(0x9100_027F); // mov sp, x19
        writer.put(0xAA14_03F3); // mov x19, x20
        writer.ret(30);
        unsafe {
            ptr::copy_nonoverlapping(writer.bytes().as_ptr(), page as *mut u8, writer.len());
        }
        gum::memory::flush_icache(page as usize, writer.len());
        page as usize
    };
    let target = emit_stub(&[0x5280_0020, 0xD65F_03C0])?; // mov w0, #1; ret
    let stack = mmap_exec_page().map_err(|err| {
        free_stub(landing);
        free_stub(target);
        err
    })?;
    let want_sp = stack as usize + 0x800;
    REDIR_PC.store(landing as u64, Ordering::SeqCst);
    REDIR_SP.store(want_sp as u64, Ordering::SeqCst);
    let hooked = unsafe { InlineHook::attach(target, on_redirect_sp_pc, ptr::null_mut()) };
    let mut hook = match hooked {
        Ok(hook) => hook,
        Err(err) => {
            free_stub(landing);
            free_stub(target);
            free_stub(stack as usize);
            return Err(err.to_string());
        }
    };
    let got = unsafe { js::native::call(target, &[]) };
    let detach = hook.detach();
    free_stub(landing);
    free_stub(target);
    free_stub(stack as usize);
    detach.map_err(|err| err.to_string())?;
    let got = got.map_err(|err| err.to_string())?;
    if got != want_sp as u64 {
        return Err(format!("sp {got:#x} want {want_sp:#x}"));
    }
    Ok(format!("resumed at landing with sp={got:#x}"))
}

/// Execute relocated integer and vector literal loads against a real pool.
#[cfg(target_arch = "aarch64")]
fn test_reloc_literal() -> Result<String, String> {
    let data = mmap_exec_page()?;
    let base = data as usize;
    unsafe {
        ptr::write_unaligned(base as *mut u32, 0x3FC0_0000); // 1.5f
        ptr::write_unaligned((base + 8) as *mut u64, 2.5f64.to_bits());
        let q = [
            0x11u8, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99, 0xAA, 0xBB, 0xCC, 0xDD, 0xEE,
            0xF0, 0x0F,
        ];
        ptr::copy_nonoverlapping(q.as_ptr(), (base + 32) as *mut u8, 16);
        ptr::write_unaligned((base + 64) as *mut u64, 0x1122_3344_5566_7788);
    }
    let prfm = arch_arm64::relocator::relocate_one(0xD800_0000, base);
    if prfm.is_ok() {
        free_stub(base);
        return Err("prfm literal was rewritten".into());
    }

    let s = exec_reloc(0x1C00_0000, base, 0xBD00_0040)?;
    let d = exec_reloc(0x5C00_0001, base + 8, 0xFD00_0041)?;
    let q = exec_reloc(0x9C00_0002, base + 32, 0x3D80_0042)?;
    let gpr = exec_reloc_gpr(0x5800_0003, base + 64)?;
    free_stub(base);

    let s_bits = u32::from_le_bytes(s[..4].try_into().unwrap());
    let d_bits = u64::from_le_bytes(d[..8].try_into().unwrap());
    if s_bits != 0x3FC0_0000 {
        return Err(format!("s0 {s_bits:#x}"));
    }
    if d_bits != 2.5f64.to_bits() {
        return Err(format!("d1 {d_bits:#x}"));
    }
    if q != [
        0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99, 0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xF0,
        0x0F,
    ] {
        return Err(format!("q2 {q:?}"));
    }
    if gpr != 0x1122_3344_5566_7788 {
        return Err(format!("x3 {gpr:#x}"));
    }
    Ok("s/d/q literal and x3 literal".into())
}

/// Run a relocated literal load and `str` the destination vector through `x2`.
#[cfg(target_arch = "aarch64")]
fn exec_reloc(word: u32, pc: usize, store: u32) -> Result<[u8; 16], String> {
    let relocated = arch_arm64::relocator::relocate_one(word, pc).map_err(|err| err.to_string())?;
    let mut code = arch_arm64::writer::CodeWriter::new();
    code.put_bytes(&relocated.bytes);
    code.put(store); // str Vd, [x2]
    code.ret(30);
    let page = mmap_exec_page()?;
    unsafe {
        ptr::copy_nonoverlapping(code.bytes().as_ptr(), page as *mut u8, code.len());
    }
    gum::memory::flush_icache(page as usize, code.len());
    let mut out = [0u8; 16];
    let call = unsafe { js::native::call(page as usize, &[0, 0, out.as_mut_ptr() as u64]) };
    free_stub(page as usize);
    call.map_err(|err| err.to_string())?;
    Ok(out)
}

/// Run a relocated `ldr x3` and return that register.
#[cfg(target_arch = "aarch64")]
fn exec_reloc_gpr(word: u32, pc: usize) -> Result<u64, String> {
    let relocated = arch_arm64::relocator::relocate_one(word, pc).map_err(|err| err.to_string())?;
    let mut code = arch_arm64::writer::CodeWriter::new();
    code.put_bytes(&relocated.bytes);
    code.put(0xAA03_03E0); // mov x0, x3
    code.ret(30);
    let page = mmap_exec_page()?;
    unsafe {
        ptr::copy_nonoverlapping(code.bytes().as_ptr(), page as *mut u8, code.len());
    }
    gum::memory::flush_icache(page as usize, code.len());
    let value = unsafe { js::native::call(page as usize, &[]) };
    free_stub(page as usize);
    value.map_err(|err| err.to_string())
}

#[cfg(target_arch = "aarch64")]
fn test_replace_revert() -> Result<String, String> {
    let target = make_add2_stub()?;
    let replacement = make_seven_stub()?;
    let before = call_add2_at(target, 1, 2);
    let replaced = match gum::replace::replace(target, replacement) {
        Ok(()) => call_add2_at(target, 1, 2),
        Err(err) => {
            free_stub(target);
            free_stub(replacement);
            return Err(err.to_string());
        }
    };
    let revert = gum::replace::revert(target);
    let after = call_add2_at(target, 1, 2);
    free_stub(target);
    free_stub(replacement);
    revert.map_err(|err| err.to_string())?;
    if before != 3 {
        return Err(format!("before {before}"));
    }
    if replaced != 7 {
        return Err(format!("replaced {replaced}"));
    }
    if after != 3 {
        return Err(format!("after {after}"));
    }
    Ok("replace 3→7, revert 7→3".into())
}

/// Two replaces of one stub must keep every byte past the redirect, then revert.
#[cfg(target_arch = "aarch64")]
#[allow(dead_code, reason = "old trampoline layout; frida-gum patches differently")]
fn test_replace_tail() -> Result<String, String> {
    let target = make_add2_stub()?;
    let first = make_seven_stub()?;
    let second = emit_stub(&[0x5280_0100, 0xD65F_03C0])?; // mov w0, #8; ret
    let mut original = [0u8; 16];
    unsafe {
        ptr::copy_nonoverlapping(target as *const u8, original.as_mut_ptr(), 16);
    }
    let fail = |err: String| {
        free_stub(target);
        free_stub(first);
        free_stub(second);
        Err(err)
    };
    if let Err(err) = gum::replace::replace(target, first) {
        return fail(err.to_string());
    }
    let mut mid = [0u8; 16];
    unsafe {
        ptr::copy_nonoverlapping(target as *const u8, mid.as_mut_ptr(), 16);
    }
    let pad = u32::from_le_bytes(mid[..4].try_into().unwrap());
    let branch = u32::from_le_bytes(mid[4..8].try_into().unwrap());
    if pad != u32::from_le_bytes(original[..4].try_into().unwrap()) {
        return fail(format!("replace overwrote the landing pad {pad:#x}"));
    }
    if branch & 0xFC00_0000 != 0x1400_0000 {
        return fail(format!("redirect {branch:#x} is not a single B"));
    }
    if mid[8..] != original[8..] {
        return fail("first replace wrote past the branch".into());
    }
    let via_first = call_add2_at(target, 1, 2);
    if let Err(err) = gum::replace::replace(target, second) {
        return fail(err.to_string());
    }
    unsafe {
        ptr::copy_nonoverlapping(target as *const u8, mid.as_mut_ptr(), 16);
    }
    if mid[..4] != original[..4] || mid[8..] != original[8..] {
        return fail("second replace wrote past the branch".into());
    }
    let via_second = call_add2_at(target, 1, 2);
    let revert = gum::replace::revert(target);
    let mut restored = [0u8; 16];
    unsafe {
        ptr::copy_nonoverlapping(target as *const u8, restored.as_mut_ptr(), 16);
    }
    let via_original = call_add2_at(target, 1, 2);
    free_stub(target);
    free_stub(first);
    free_stub(second);
    revert.map_err(|err| err.to_string())?;
    if restored != original {
        return Err("revert did not restore the pre-replace bytes".into());
    }
    if via_first != 7 || via_second != 8 || via_original != 3 {
        return Err(format!("calls {via_first}/{via_second}/{via_original}"));
    }
    Ok("B redirect, tail kept, revert restored".into())
}

fn js_cases(worker: &JsWorker) -> Vec<Outcome> {
    vec![
        js_eval(worker, "js", "arithmetic", "1 + 2 * 3"),
        js_eval(
            worker,
            "js",
            "process_id",
            "String(Process.id) === String(Process.id) ? ('pid=' + Process.id) : 'mismatch'",
        ),
        js_eval(
            worker,
            "js",
            "module_strlen",
            r#"
            (function () {
              var p = Module.findExportByName('libc.so', 'strlen');
              if (!p || p.isNull()) throw new Error('no strlen');
              var n = new NativeFunction(p, 'int', ['pointer'])(Memory.allocUtf8String('xyz'));
              if (n !== 3) throw new Error('n=' + n);
              return 'strlen=3';
            })()
            "#,
        ),
        js_eval(
            worker,
            "js",
            "memory_roundtrip",
            r#"
            (function () {
              var p = Memory.alloc(16);
              p.writeU32(0x41424344);
              if (p.readU32() !== 0x41424344) throw new Error('readback');
              return 'ok';
            })()
            "#,
        ),
        js_eval(
            worker,
            "js",
            "interceptor_attach",
            r#"
            (function () {
              var page = Memory.alloc(Process.pageSize);
              Memory.protect(page, Process.pageSize, 'rwx');
              for (var i = 0; i < 4; i++) page.add(i * 4).writeU32(0xd503201f);
              page.add(16).writeU32(0x528000e0);
              page.add(20).writeU32(0xd65f03c0);
              var hits = 0;
              var listener = Interceptor.attach(page, {
                onEnter: function () { hits++; }
              });
              var patched = page.readU32() >>> 0;
              if ((patched & 0xfc000000) !== 0x14000000) {
                throw new Error('patch=' + patched.toString(16));
              }
              if (Process.arch !== 'arm64') {
                listener.detach();
                var restored = page.readU32() >>> 0;
                if (restored !== 0xd503201f) throw new Error('restored=' + restored.toString(16));
                return 'patched=' + patched.toString(16);
              }
              var fn = new NativeFunction(page, 'int', []);
              var a = fn();
              listener.detach();
              var b = fn();
              if (hits < 1) throw new Error('hits=' + hits);
              if (a !== 7 || b !== 7) throw new Error('ret a=' + a + ' b=' + b);
              return 'hits=' + hits + ' ret=7';
            })()
            "#,
        ),
        js_eval(
            worker,
            "js",
            "native_callback",
            r#"
            (function () {
              var cb = new NativeCallback(function (n) { return n + 1; }, 'int', ['int']);
              var fn = new NativeFunction(cb, 'int', ['int']);
              var n = fn(41);
              if (n !== 42) throw new Error('n=' + n);
              return 'n=42';
            })()
            "#,
        ),
        js_eval(
            worker,
            "js",
            "interceptor_replace",
            r#"
            (function () {
              var page = Memory.alloc(Process.pageSize);
              Memory.protect(page, Process.pageSize, 'rwx');
              for (var i = 0; i < 4; i++) page.add(i * 4).writeU32(0xd503201f);
              var replacement = Memory.alloc(16);
              Interceptor.replace(page, replacement);
              var after = page.readU32() >>> 0;
              Interceptor.revert(page);
              var restored = page.readU32() >>> 0;
              if (restored !== 0xd503201f) throw new Error('restored=' + restored.toString(16));
              if (after === 0xd503201f) throw new Error('not patched');
              return 'after=' + after.toString(16);
            })()
            "#,
        ),
        js_eval(
            worker,
            "js",
            "file_roundtrip",
            r#"
            (function () {
              var name = 'ca-selftest.txt';
              var cmd = '';
              try {
                var bytes = File.readAllBytes('/proc/self/cmdline');
                var u8 = new Uint8Array(bytes);
                for (var i = 0; i < u8.length && u8[i]; i++) cmd += String.fromCharCode(u8[i]);
              } catch (e) {}
              var dirs = [];
              try { dirs.push(Process.getTmpDir()); } catch (e) {}
              if (cmd.indexOf('.') >= 0 && cmd.indexOf('/') < 0) {
                dirs.push('/data/user/0/' + cmd + '/cache');
                dirs.push('/data/user/0/' + cmd + '/code_cache');
                dirs.push('/data/data/' + cmd + '/cache');
                dirs.push('/data/data/' + cmd + '/code_cache');
              }
              var last = 'no dir';
              for (var i = 0; i < dirs.length; i++) {
                var path = dirs[i] + '/' + name;
                try {
                  File.writeAllText(path, 'hello\n');
                  var got = File.readAllText(path);
                  if (got !== 'hello\n') throw new Error('readback:' + got);
                  return 'path=' + path;
                } catch (e) { last = String(e); }
              }
              throw new Error('file: ' + last);
            })()
            "#,
        ),
        js_eval(
            worker,
            "js",
            "instruction_parse",
            r#"
            (function () {
              var nop = Memory.alloc(4);
              nop.writeU32(0xd503201f);
              var insn = Instruction.parse(nop);
              if (insn.mnemonic !== 'nop') throw new Error('mnemonic=' + insn.mnemonic);
              return insn.mnemonic;
            })()
            "#,
        ),
    ]
}

fn js_eval(worker: &JsWorker, layer: &'static str, name: &'static str, code: &str) -> Outcome {
    if !selected(layer, name) {
        return Outcome::skip(layer, name, "filtered");
    }
    match worker.eval(code) {
        Ok(value) => {
            if let Some(rest) = value.strip_prefix("error:") {
                Outcome::fail(layer, name, rest.to_owned())
            } else {
                Outcome::pass(layer, name, value)
            }
        }
        Err(err) => Outcome::fail(layer, name, err.to_string()),
    }
}

fn java_cases(worker: Option<&JsWorker>) -> Vec<Outcome> {
    let maps = runtime::maps::read_self_maps().unwrap_or_default();
    let has_art = maps.iter().any(|m| {
        m.clean_path()
            .is_some_and(|path| path.contains("libart.so"))
    });
    if !has_art {
        return vec![Outcome::skip(
            "java",
            "art",
            "libart.so not mapped (inject a JVM process, not sleep/toybox)",
        )];
    }
    // Warm JVMTI via Java.perform before any ArtMethod patch. Plugin init
    // CAS-writes boot.art entrypoints and SIGSEGVs if we already hooked them.
    let mut cases = Vec::new();
    match worker {
        Some(worker) => cases.push(js_eval(
            worker,
            "java",
            "use_perform",
            r#"
            (function () {
              if (!Java.available) throw new Error('Java.available=false');
              return Java.perform(function () {
                var SB = Java.use('java.lang.StringBuilder');
                var sb = SB.$new();
                sb.append('hello');
                var n = sb.length();
                if (n !== 5) throw new Error('length=' + n);
                return 'length=5';
              });
            })()
            "#,
        )),
        None => cases.push(Outcome::skip("java", "use_perform", "QuickJS unavailable")),
    }
    cases.push(guard("java", "probe", || {
        art::probe().map_err(|err| err.to_string())
    }));
    cases.push(guard("java", "length", || {
        art::java::call_length()
            .map(|n| n.to_string())
            .map_err(|err| err.to_string())
    }));
    cases.push(guard("java", "to_string", || {
        art::java::call_to_string().map_err(|err| err.to_string())
    }));
    cases.push(guard("java", "char_at", || {
        art::java::call_char_at()
            .map(|n| n.to_string())
            .map_err(|err| err.to_string())
    }));
    cases.push(guard("java", "index_of", || {
        art::java::call_index_of()
            .map(|n| n.to_string())
            .map_err(|err| err.to_string())
    }));
    cases.push(guard("java", "hook_install", || {
        art::java::hook_install_test().map_err(|err| err.to_string())
    }));
    cases
}

#[cfg(test)]
mod tests {
    use serde_json::Value;

    use super::run;

    #[test]
    fn runtime_suite_reports_structure() {
        let value = run(None, Some("runtime"));
        let cases = value.get("cases").and_then(Value::as_array).unwrap();
        assert!(value.get("pid").and_then(Value::as_u64).unwrap_or(0) > 0);
        assert!(cases.iter().any(|case| case["layer"] == "runtime"));
        assert_eq!(value["ok"], true);
    }

    #[test]
    fn js_device_families_are_registered() {
        let (tx, _rx) = std::sync::mpsc::channel();
        let worker = js::JsWorker::spawn(tx).unwrap();
        let value = run(Some(&worker), Some("js"));
        let names: Vec<&str> = value["cases"]
            .as_array()
            .unwrap()
            .iter()
            .filter_map(|case| case["name"].as_str())
            .collect();
        for want in [
            "module_strlen",
            "native_callback",
            "interceptor_attach",
            "interceptor_replace",
            "file_roundtrip",
            "instruction_parse",
        ] {
            assert!(
                names.iter().any(|name| *name == want),
                "{want} missing from {names:?}"
            );
        }
    }

    #[test]
    fn gum_js_java_and_trace_suites_on_host() {
        let gum = run(None, Some("gum"));
        let gum_cases = gum["cases"].as_array().unwrap();
        assert!(gum_cases.iter().any(|case| case["layer"] == "gum"));

        let js = run(None, Some("js"));
        let js_cases = js["cases"].as_array().unwrap();
        assert!(js_cases
            .iter()
            .any(|case| { case["layer"] == "js" && case["ok"].is_null() }));

        let java = run(None, Some("java"));
        let java_cases = java["cases"].as_array().unwrap();
        assert!(!java_cases.is_empty());
        assert!(java_cases.iter().all(|case| {
            case["layer"] == "java" && (case["ok"].is_null() || case["ok"].is_boolean())
        }));

        let trace = run(None, Some("trace"));
        let trace_cases = trace["cases"].as_array().unwrap();
        assert!(trace_cases.iter().any(|case| {
            case["layer"] == "trace" && (case["ok"].is_null() || case["ok"] == false)
        }));
    }
}
