//! `Il2Cpp` script object. The runtime lives in the `il2cpp` crate.

use rquickjs::{Array, Ctx, Result as JsResult, Value};

use crate::api::to_js_error;

pub fn install<'js>(ctx: &Ctx<'js>) -> JsResult<()> {
    crate::il2cpp_api::install(ctx)
}

pub(crate) fn summary() -> JsResult<String> {
    let value = il2cpp::summary().map_err(to_js_error)?;
    serde_json::to_string(&value).map_err(|err| to_js_error(err.to_string()))
}

pub(crate) fn assemblies<'js>(ctx: Ctx<'js>) -> JsResult<Array<'js>> {
    let rt = il2cpp::Runtime::session().map_err(to_js_error)?;
    let list = rt
        .domain()
        .map_err(to_js_error)?
        .assemblies(&rt)
        .map_err(to_js_error)?;
    let array = Array::new(ctx)?;
    for (index, assembly) in list.iter().enumerate() {
        array.set(index, assembly.name(&rt).map_err(to_js_error)?)?;
    }
    Ok(array)
}

pub(crate) fn classes<'js>(
    ctx: Ctx<'js>,
    assembly: String,
    limit: Value<'js>,
) -> JsResult<Array<'js>> {
    let rt = il2cpp::Runtime::session().map_err(to_js_error)?;
    let image = rt
        .domain()
        .map_err(to_js_error)?
        .assembly(&rt, &assembly)
        .map_err(to_js_error)?
        .image(&rt)
        .map_err(to_js_error)?;
    let mut classes = image.classes(&rt).map_err(to_js_error)?;
    if let Some(limit) = limit.as_int() {
        if limit >= 0 {
            classes.truncate(limit as usize);
        }
    }
    let array = Array::new(ctx)?;
    for (index, class) in classes.iter().enumerate() {
        array.set(index, class.full_name(&rt).map_err(to_js_error)?)?;
    }
    Ok(array)
}

pub(crate) fn methods<'js>(
    ctx: Ctx<'js>,
    assembly: String,
    class_name: String,
) -> JsResult<Array<'js>> {
    let rt = il2cpp::Runtime::session().map_err(to_js_error)?;
    let class = rt
        .domain()
        .map_err(to_js_error)?
        .assembly(&rt, &assembly)
        .map_err(to_js_error)?
        .image(&rt)
        .map_err(to_js_error)?
        .class(&rt, &class_name)
        .map_err(to_js_error)?;
    let methods = class.methods(&rt).map_err(to_js_error)?;
    let array = Array::new(ctx)?;
    for (index, method) in methods.iter().enumerate() {
        array.set(index, method.signature(&rt).map_err(to_js_error)?)?;
    }
    Ok(array)
}

pub(crate) fn dump(assembly: String, path: String, limit: Value) -> JsResult<String> {
    let rt = il2cpp::Runtime::session().map_err(to_js_error)?;
    let cap = limit
        .as_int()
        .filter(|limit| *limit >= 0)
        .map(|limit| limit as usize);
    let text = il2cpp::dump_assembly(&rt, Some(assembly.as_str()), cap).map_err(to_js_error)?;
    if !path.is_empty() {
        std::fs::write(&path, &text).map_err(|err| to_js_error(err.to_string()))?;
    }
    Ok(format!("classes_text={}", text.lines().count()))
}
