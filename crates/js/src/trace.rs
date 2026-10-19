//! Eval `Trace.function` / `Trace.exclude` (TAL-style QBDI door).

use rquickjs::function::Opt;
use rquickjs::prelude::Func;
use rquickjs::{Array, Ctx, Function, Object, Result as JsResult, Value};

use qbdi::{begin, exclude_module, take_events, Escape, EventKind, EventMask, TraceConfig};

use crate::api::{parse_pointer, to_js_error, NativePointer};

pub fn install<'js>(ctx: &Ctx<'js>) -> JsResult<()> {
    let trace = Object::new(ctx.clone())?;
    trace.set("function", Func::from(trace_function))?;
    trace.set(
        "exclude",
        Func::from(|name: String| {
            exclude_module(name);
        }),
    )?;
    trace.set("takeEvents", Func::from(take_events_js))?;
    ctx.globals().set("Trace", trace)?;
    Ok(())
}

fn trace_function<'js>(
    ctx: Ctx<'js>,
    target: Value<'js>,
    options: Opt<Object<'js>>,
) -> JsResult<()> {
    let mut config = TraceConfig::new(parse_pointer(&target)?);
    if let Some(options) = options.0 {
        if let Ok(module) = options.get::<_, String>("module") {
            config.module = Some(module);
        }
        if let Ok(until) = options.get::<_, Value<'js>>("until") {
            if !until.is_undefined() && !until.is_null() {
                config.until = Some(parse_pointer(&until)?);
            }
        }
        if let Ok(events) = options.get::<_, Array<'js>>("events") {
            let mut names = Vec::new();
            for index in 0..events.len() {
                names.push(events.get::<String>(index)?);
            }
            config.events = EventMask::from_names(&names);
        }
        if let Ok(exclude) = options.get::<_, Array<'js>>("exclude") {
            for index in 0..exclude.len() {
                config.extra_exclude.push(exclude.get::<String>(index)?);
            }
        }
        if let Ok(escape) = options.get::<_, Array<'js>>("escape") {
            for index in 0..escape.len() {
                let item: Object<'js> = escape.get(index)?;
                let break_at = parse_pointer(&item.get::<_, Value<'js>>("break")?)?;
                let resume = parse_pointer(&item.get::<_, Value<'js>>("resume")?)?;
                config.escapes.push(Escape { break_at, resume });
            }
        }
        let _ = options.get::<_, Function<'js>>("onEvent");
    }
    begin(config).map_err(to_js_error)?;
    let _ = ctx;
    Ok(())
}

fn take_events_js<'js>(ctx: Ctx<'js>) -> JsResult<Array<'js>> {
    let events = take_events();
    let array = Array::new(ctx.clone())?;
    for (index, event) in events.into_iter().enumerate() {
        let item = Object::new(ctx.clone())?;
        let kind = match event.kind {
            EventKind::Inst => "inst",
            EventKind::Mem => "mem",
            EventKind::Call => "call",
        };
        item.set("type", kind)?;
        item.set("pc", NativePointer::instance(ctx.clone(), event.pc)?)?;
        item.set("size", event.size)?;
        if event.kind == EventKind::Mem {
            item.set(
                "address",
                NativePointer::instance(ctx.clone(), event.mem_addr)?,
            )?;
            item.set("value", event.mem_value)?;
            item.set("write", event.is_write)?;
        }
        array.set(index, item)?;
    }
    Ok(array)
}
