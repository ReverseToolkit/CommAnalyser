//! Frida gumjs APIs that sit on top of `runtime` / `gum`.

use std::cell::{Cell, RefCell};
use std::collections::VecDeque;
use std::fs::{File as FsFile, OpenOptions};
use std::io::{Read, Seek, SeekFrom, Write};
use std::path::Path;
use std::sync::{Arc, Condvar, Mutex};
use std::time::{Duration, Instant};

use rquickjs::function::Opt;
use rquickjs::prelude::Func;
use rquickjs::{Array, ArrayBuffer, Ctx, Function, Object, Persistent, Result as JsResult, Value};

use runtime::module;

use crate::api::{js_error, parse_pointer, to_js_error, NativePointer};

thread_local! {
    static TIMERS: RefCell<Vec<Timer>> = const { RefCell::new(Vec::new()) };
    static NEXT_TIMER: Cell<u32> = const { Cell::new(1) };
    static RECV: RefCell<Option<Arc<RecvQueue>>> = const { RefCell::new(None) };
    static HW_BREAK: RefCell<Vec<(u32, u64)>> = const { RefCell::new(Vec::new()) };
    static HW_WATCH: RefCell<Vec<(u32, u64)>> = const { RefCell::new(Vec::new()) };
}

struct Timer {
    id: u32,
    when: Instant,
    interval: Option<Duration>,
    function: Persistent<Function<'static>>,
}

pub struct RecvQueue {
    messages: Mutex<VecDeque<String>>,
    wait: Condvar,
}

impl RecvQueue {
    pub fn new() -> Arc<Self> {
        Arc::new(Self {
            messages: Mutex::new(VecDeque::new()),
            wait: Condvar::new(),
        })
    }

    pub fn post(&self, json: String) {
        self.messages
            .lock()
            .unwrap_or_else(|err| err.into_inner())
            .push_back(json);
        self.wait.notify_all();
    }

    fn pop_wait(&self) -> Option<String> {
        let mut guard = self.messages.lock().unwrap_or_else(|err| err.into_inner());
        loop {
            if let Some(message) = guard.pop_front() {
                return Some(message);
            }
            guard = self.wait.wait(guard).unwrap_or_else(|err| err.into_inner());
        }
    }
}

pub fn bind_recv_queue(queue: Arc<RecvQueue>) {
    RECV.with(|slot| {
        if slot.borrow().is_none() {
            *slot.borrow_mut() = Some(queue);
        }
    });
}

pub fn next_timer_wait() -> Duration {
    TIMERS.with(|timers| {
        timers
            .borrow()
            .iter()
            .map(|timer| timer.when.saturating_duration_since(Instant::now()))
            .min()
            .unwrap_or(Duration::from_secs(60))
    })
}

pub fn fire_due_timers(ctx: &Ctx<'_>) {
    let now = Instant::now();
    let due: Vec<(u32, Option<Duration>, Persistent<Function<'static>>)> = TIMERS.with(|timers| {
        let mut timers = timers.borrow_mut();
        let mut due = Vec::new();
        timers.retain(|timer| {
            if timer.when <= now {
                due.push((timer.id, timer.interval, timer.function.clone()));
                timer.interval.is_some()
            } else {
                true
            }
        });
        if !due.is_empty() {
            for timer in timers.iter_mut() {
                if let Some((_, interval, _)) = due.iter().find(|(id, _, _)| *id == timer.id) {
                    if let Some(interval) = interval {
                        timer.when = Instant::now() + *interval;
                    }
                }
            }
        }
        due
    });
    for (_, _, function) in due {
        if let Ok(function) = function.restore(ctx) {
            let _ = function.call::<(), ()>(());
        }
    }
}

/// Install File, ModuleMap, DebugSymbol extras, timers, recv, and remaining gumjs names.
pub fn install<'js>(ctx: &Ctx<'js>) -> JsResult<()> {
    install_timers(ctx)?;
    install_recv(ctx)?;
    install_file(ctx)?;
    install_module_map(ctx)?;
    Ok(())
}

fn install_timers<'js>(ctx: &Ctx<'js>) -> JsResult<()> {
    ctx.globals().set(
        "setTimeout",
        Func::from(
            |ctx: Ctx<'js>, function: Function<'js>, delay: Opt<f64>| -> u32 {
                schedule(&ctx, function, delay.0.unwrap_or(0.0), None)
            },
        ),
    )?;
    ctx.globals().set(
        "setInterval",
        Func::from(
            |ctx: Ctx<'js>, function: Function<'js>, delay: Opt<f64>| -> u32 {
                let ms = delay.0.unwrap_or(0.0).max(0.0);
                schedule(&ctx, function, ms, Some(Duration::from_millis(ms as u64)))
            },
        ),
    )?;
    ctx.globals().set("clearTimeout", Func::from(clear_timer))?;
    ctx.globals()
        .set("clearInterval", Func::from(clear_timer))?;
    ctx.globals().set(
        "setImmediate",
        Func::from(|ctx: Ctx<'js>, function: Function<'js>| -> u32 {
            schedule(&ctx, function, 0.0, None)
        }),
    )?;
    ctx.globals()
        .set("clearImmediate", Func::from(clear_timer))?;
    Ok(())
}

fn schedule<'js>(
    ctx: &Ctx<'js>,
    function: Function<'js>,
    delay_ms: f64,
    interval: Option<Duration>,
) -> u32 {
    let id = NEXT_TIMER.with(|slot| {
        let id = slot.get();
        slot.set(id.saturating_add(1));
        id
    });
    let delay = Duration::from_millis(delay_ms.max(0.0) as u64);
    let function = Persistent::save(ctx, function);
    TIMERS.with(|timers| {
        timers.borrow_mut().push(Timer {
            id,
            when: Instant::now() + delay,
            interval,
            function,
        });
    });
    id
}

fn clear_timer(id: u32) {
    TIMERS.with(|timers| timers.borrow_mut().retain(|timer| timer.id != id));
}

fn install_recv<'js>(ctx: &Ctx<'js>) -> JsResult<()> {
    ctx.globals().set(
        "recv",
        Func::from(
            |ctx: Ctx<'js>,
             first: Value<'js>,
             second: Opt<Function<'js>>|
             -> JsResult<Object<'js>> {
                let (filter, callback) = if first.as_function().is_some() {
                    ("*".to_owned(), first.get::<Function>()?)
                } else if let Some(callback) = second.0 {
                    let filter = first.get::<String>().unwrap_or_else(|_| "*".to_owned());
                    (filter, callback)
                } else {
                    return Err(js_error("recv: expected a callback"));
                };
                let callback = Persistent::save(&ctx, callback);
                let op = Object::new(ctx.clone())?;
                op.set(
                    "wait",
                    Func::from({
                        let filter = filter.clone();
                        move |ctx: Ctx<'js>| -> JsResult<()> {
                            wait_message(&ctx, &filter, &callback)
                        }
                    }),
                )?;
                Ok(op)
            },
        ),
    )?;
    Ok(())
}

fn wait_message(
    ctx: &Ctx<'_>,
    filter: &str,
    callback: &Persistent<Function<'static>>,
) -> JsResult<()> {
    let queue = RECV.with(|slot| slot.borrow().clone());
    let Some(queue) = queue else {
        return Err(js_error("recv: no message queue"));
    };
    loop {
        let Some(text) = queue.pop_wait() else {
            continue;
        };
        let parse: Function = ctx.eval("JSON.parse")?;
        let message: Value = parse.call((text,))?;
        let type_name = message
            .as_object()
            .and_then(|object| object.get::<_, String>("type").ok())
            .unwrap_or_default();
        if filter != "*" && type_name != filter {
            continue;
        }
        let callback = callback.clone().restore(ctx)?;
        callback.call::<_, ()>((message,))?;
        return Ok(());
    }
}

fn install_file<'js>(ctx: &Ctx<'js>) -> JsResult<()> {
    ctx.eval::<(), _>(
        r#"
        globalThis.File = function File(path, mode) {
            return __analyser_file_open(String(path), mode == null ? 'r' : String(mode));
        };
        File.SEEK_SET = 0;
        File.SEEK_CUR = 1;
        File.SEEK_END = 2;
        File.readAllText = function (path) { return __analyser_file_read_text(String(path)); };
        File.writeAllText = function (path, text) { __analyser_file_write_text(String(path), String(text)); };
        File.readAllBytes = function (path) { return __analyser_file_read_bytes(String(path)); };
        File.writeAllBytes = function (path, bytes) { __analyser_file_write_bytes(String(path), bytes); };
        "#,
    )?;
    ctx.globals()
        .set("__analyser_file_open", Func::from(file_open))?;
    ctx.globals().set(
        "__analyser_file_read_text",
        Func::from(|path: String| -> JsResult<String> {
            std::fs::read_to_string(&path).map_err(|err| js_error(err.to_string()))
        }),
    )?;
    ctx.globals().set(
        "__analyser_file_write_text",
        Func::from(|path: String, text: String| -> JsResult<()> {
            std::fs::write(&path, text).map_err(|err| js_error(err.to_string()))
        }),
    )?;
    ctx.globals().set(
        "__analyser_file_read_bytes",
        Func::from(
            |ctx: Ctx<'js>, path: String| -> JsResult<ArrayBuffer<'js>> {
                let bytes = std::fs::read(&path).map_err(|err| js_error(err.to_string()))?;
                ArrayBuffer::new(ctx, bytes)
            },
        ),
    )?;
    ctx.globals().set(
        "__analyser_file_write_bytes",
        Func::from(|path: String, data: ArrayBuffer<'js>| -> JsResult<()> {
            // SAFETY: ArrayBuffer is live for this call.
            let bytes = unsafe { data.as_bytes() }.unwrap_or(&[]);
            std::fs::write(&path, bytes).map_err(|err| js_error(err.to_string()))
        }),
    )?;
    Ok(())
}

fn file_open<'js>(ctx: Ctx<'js>, path: String, mode: String) -> JsResult<Object<'js>> {
    let mut options = OpenOptions::new();
    match mode.as_str() {
        "r" | "rb" => {
            options.read(true);
        }
        "w" | "wb" => {
            options.write(true).create(true).truncate(true);
        }
        "a" | "ab" => {
            options.write(true).create(true).append(true);
        }
        "r+" | "rb+" => {
            options.read(true).write(true);
        }
        "w+" | "wb+" => {
            options.read(true).write(true).create(true).truncate(true);
        }
        _ => {
            options.read(true).write(true).create(true);
        }
    }
    let file = options
        .open(&path)
        .map_err(|err| js_error(err.to_string()))?;
    let file = RcFile(std::rc::Rc::new(RefCell::new(Some(file))));
    let obj = Object::new(ctx.clone())?;
    obj.set(
        "tell",
        Func::from({
            let file = file.clone();
            move || -> JsResult<i64> {
                let mut slot = file.0.borrow_mut();
                let handle = slot.as_mut().ok_or_else(|| js_error("file closed"))?;
                handle
                    .stream_position()
                    .map(|pos| pos as i64)
                    .map_err(|err| js_error(err.to_string()))
            }
        }),
    )?;
    obj.set(
        "seek",
        Func::from({
            let file = file.clone();
            move |offset: i64, whence: Opt<i32>| -> JsResult<i64> {
                let mut slot = file.0.borrow_mut();
                let handle = slot.as_mut().ok_or_else(|| js_error("file closed"))?;
                let from = match whence.0.unwrap_or(0) {
                    1 => SeekFrom::Current(offset),
                    2 => SeekFrom::End(offset),
                    _ => SeekFrom::Start(offset.max(0) as u64),
                };
                handle
                    .seek(from)
                    .map(|pos| pos as i64)
                    .map_err(|err| js_error(err.to_string()))
            }
        }),
    )?;
    obj.set(
        "readText",
        Func::from({
            let file = file.clone();
            move |size: Opt<i32>| -> JsResult<String> {
                let mut slot = file.0.borrow_mut();
                let handle = slot.as_mut().ok_or_else(|| js_error("file closed"))?;
                let mut buf = String::new();
                if let Some(size) = size.0.filter(|n| *n >= 0) {
                    let mut bytes = vec![0u8; size as usize];
                    let n = handle
                        .read(&mut bytes)
                        .map_err(|err| js_error(err.to_string()))?;
                    Ok(String::from_utf8_lossy(&bytes[..n]).into_owned())
                } else {
                    handle
                        .read_to_string(&mut buf)
                        .map_err(|err| js_error(err.to_string()))?;
                    Ok(buf)
                }
            }
        }),
    )?;
    obj.set(
        "readLine",
        Func::from({
            let file = file.clone();
            move || -> JsResult<String> {
                let mut slot = file.0.borrow_mut();
                let handle = slot.as_mut().ok_or_else(|| js_error("file closed"))?;
                let mut buf = Vec::new();
                let mut byte = [0u8; 1];
                loop {
                    let n = handle
                        .read(&mut byte)
                        .map_err(|err| js_error(err.to_string()))?;
                    if n == 0 {
                        break;
                    }
                    buf.push(byte[0]);
                    if byte[0] == b'\n' {
                        break;
                    }
                }
                Ok(String::from_utf8_lossy(&buf).into_owned())
            }
        }),
    )?;
    obj.set(
        "write",
        Func::from({
            let file = file.clone();
            move |text: String| -> JsResult<()> {
                let mut slot = file.0.borrow_mut();
                let handle = slot.as_mut().ok_or_else(|| js_error("file closed"))?;
                handle
                    .write_all(text.as_bytes())
                    .map_err(|err| js_error(err.to_string()))
            }
        }),
    )?;
    obj.set(
        "flush",
        Func::from({
            let file = file.clone();
            move || -> JsResult<()> {
                let mut slot = file.0.borrow_mut();
                let handle = slot.as_mut().ok_or_else(|| js_error("file closed"))?;
                handle.flush().map_err(|err| js_error(err.to_string()))
            }
        }),
    )?;
    obj.set(
        "close",
        Func::from({
            let file = file.clone();
            move || {
                *file.0.borrow_mut() = None;
            }
        }),
    )?;
    let _ = path;
    Ok(obj)
}

#[derive(Clone)]
struct RcFile(std::rc::Rc<RefCell<Option<FsFile>>>);

fn install_module_map<'js>(ctx: &Ctx<'js>) -> JsResult<()> {
    ctx.eval::<(), _>(
        r#"
        globalThis.ModuleMap = function ModuleMap(filter) {
            return __analyser_module_map(filter);
        };
        globalThis.SystemFunction = globalThis.NativeFunction;
        "#,
    )?;
    ctx.globals().set(
        "__analyser_module_map",
        Func::from(
            |ctx: Ctx<'js>, filter: Opt<Value<'js>>| -> JsResult<Object<'js>> {
                let callback = filter.0.and_then(|value| value.get::<Function>().ok());
                module_map_object(ctx, callback)
            },
        ),
    )?;
    Ok(())
}

fn module_map_object<'js>(ctx: Ctx<'js>, filter: Option<Function<'js>>) -> JsResult<Object<'js>> {
    let modules = collect_modules(filter.as_ref())?;
    let store = std::rc::Rc::new(RefCell::new(modules));
    let obj = Object::new(ctx.clone())?;
    obj.set(
        "has",
        Func::from({
            let store = store.clone();
            move |address: Value<'js>| -> JsResult<bool> {
                let addr = parse_pointer(&address)? as usize;
                Ok(store.borrow().iter().any(|module| module.contains(addr)))
            }
        }),
    )?;
    obj.set(
        "find",
        Func::from({
            let store = store.clone();
            move |ctx: Ctx<'js>, address: Value<'js>| -> JsResult<Value<'js>> {
                let addr = parse_pointer(&address)? as usize;
                match store.borrow().iter().find(|module| module.contains(addr)) {
                    Some(module) => Ok(crate::api::module_object_from(ctx, module)?.into_value()),
                    None => Ok(Value::new_null(ctx)),
                }
            }
        }),
    )?;
    obj.set(
        "findName",
        Func::from({
            let store = store.clone();
            move |ctx: Ctx<'js>, address: Value<'js>| -> JsResult<Value<'js>> {
                let addr = parse_pointer(&address)? as usize;
                match store.borrow().iter().find(|module| module.contains(addr)) {
                    Some(module) => module.name.clone().into_js_local(&ctx),
                    None => Ok(Value::new_null(ctx)),
                }
            }
        }),
    )?;
    obj.set(
        "findPath",
        Func::from({
            let store = store.clone();
            move |ctx: Ctx<'js>, address: Value<'js>| -> JsResult<Value<'js>> {
                let addr = parse_pointer(&address)? as usize;
                match store.borrow().iter().find(|module| module.contains(addr)) {
                    Some(module) => module.path.clone().into_js_local(&ctx),
                    None => Ok(Value::new_null(ctx)),
                }
            }
        }),
    )?;
    obj.set(
        "update",
        Func::from({
            let store = store.clone();
            move || -> JsResult<()> {
                *store.borrow_mut() = module::enumerate().map_err(to_js_error)?;
                Ok(())
            }
        }),
    )?;
    obj.set(
        "values",
        Func::from({
            let store = store.clone();
            move |ctx: Ctx<'js>| -> JsResult<Array<'js>> {
                let modules = store.borrow().clone();
                let array = Array::new(ctx.clone())?;
                for (index, module) in modules.iter().enumerate() {
                    array.set(index, crate::api::module_object_from(ctx.clone(), module)?)?;
                }
                Ok(array)
            }
        }),
    )?;
    Ok(obj)
}

fn collect_modules(filter: Option<&Function<'_>>) -> JsResult<Vec<module::Module>> {
    let modules = module::enumerate().map_err(to_js_error)?;
    let Some(filter) = filter else {
        return Ok(modules);
    };
    let mut kept = Vec::new();
    for module in modules {
        let name = module.name.clone();
        let keep: bool = filter.call((name,)).unwrap_or(true);
        if keep {
            kept.push(module);
        }
    }
    Ok(kept)
}

trait IntoJsLocal<'js> {
    fn into_js_local(self, ctx: &Ctx<'js>) -> JsResult<Value<'js>>;
}

impl<'js> IntoJsLocal<'js> for String {
    fn into_js_local(self, ctx: &Ctx<'js>) -> JsResult<Value<'js>> {
        use rquickjs::IntoJs;
        self.into_js(ctx)
    }
}

pub fn hw_set_breakpoint(id: u32, address: u64) {
    HW_BREAK.with(|slot| {
        let mut table = slot.borrow_mut();
        table.retain(|(existing, _)| *existing != id);
        table.push((id, address));
    });
}

pub fn hw_unset_breakpoint(id: u32) {
    HW_BREAK.with(|slot| slot.borrow_mut().retain(|(existing, _)| *existing != id));
}

pub fn hw_set_watchpoint(id: u32, address: u64) {
    HW_WATCH.with(|slot| {
        let mut table = slot.borrow_mut();
        table.retain(|(existing, _)| *existing != id);
        table.push((id, address));
    });
}

pub fn hw_unset_watchpoint(id: u32) {
    HW_WATCH.with(|slot| slot.borrow_mut().retain(|(existing, _)| *existing != id));
}

pub fn load_module(path: &str) -> runtime::Result<module::Module> {
    let c_path = std::ffi::CString::new(path)
        .map_err(|_| runtime::Error::Parse("Module.load: NUL in path".into()))?;
    // SAFETY: dlopen reads the path; RTLD_NOW matches Frida's Module.load.
    let handle = unsafe { libc::dlopen(c_path.as_ptr(), libc::RTLD_NOW) };
    if handle.is_null() {
        let err = unsafe { std::ffi::CStr::from_ptr(libc::dlerror()) };
        return Err(runtime::Error::Parse(format!(
            "Module.load: {}",
            err.to_string_lossy()
        )));
    }
    let name = Path::new(path)
        .file_name()
        .and_then(|name| name.to_str())
        .unwrap_or(path);
    module::find_by_name(name)?
        .ok_or_else(|| runtime::Error::NotFound(format!("loaded {path} but maps miss it")))
}

pub fn ensure_initialized(path: &str) -> runtime::Result<()> {
    let c_path = std::ffi::CString::new(path)
        .map_err(|_| runtime::Error::Parse("ensureInitialized: NUL in path".into()))?;
    // SAFETY: RTLD_NOLOAD re-enters init on an already mapped object.
    let handle = unsafe { libc::dlopen(c_path.as_ptr(), libc::RTLD_NOLOAD | libc::RTLD_NOW) };
    if handle.is_null() {
        let _ = load_module(path)?;
    }
    Ok(())
}

pub fn debugger_attached() -> bool {
    std::fs::read_to_string("/proc/self/status")
        .ok()
        .and_then(|text| {
            text.lines()
                .find(|line| line.starts_with("TracerPid:"))
                .and_then(|line| line.split_whitespace().nth(1))
                .and_then(|pid| pid.parse::<u32>().ok())
        })
        .is_some_and(|pid| pid != 0)
}

pub fn range_object<'js>(
    ctx: Ctx<'js>,
    base: usize,
    size: usize,
    protection: &str,
    file: Option<&str>,
) -> JsResult<Object<'js>> {
    let obj = Object::new(ctx.clone())?;
    obj.set("base", NativePointer::instance(ctx.clone(), base as u64)?)?;
    obj.set("size", size)?;
    obj.set("protection", protection)?;
    if let Some(file) = file {
        obj.set("file", file)?;
    }
    Ok(obj)
}
