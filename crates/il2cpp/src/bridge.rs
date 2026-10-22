//! Script-facing operations that match `frida-il2cpp-bridge`.
//!
//! Overload scoring, generic inflation, `gc.choose`, application lookup and
//! unboxing live here. The QuickJS object graph calls them.

use crate::mem;
use crate::runtime::{Class, Method, Runtime, Type};
use runtime::{Error, Result};

/// A parameter type in an overload search. A class scores higher than a name
/// when the parameter is that class or a base of it.
pub enum OverloadSpec {
    Name(String),
    Class(Class),
}

impl Method {
    /// Pick the overload closest to `specs`, using the same scores as the
    /// TypeScript bridge: exact type 2, assignable base 1.
    pub fn overload(&self, rt: &Runtime, specs: &[OverloadSpec]) -> Result<Method> {
        let name = self.name(rt)?;
        let mut best: Option<(i32, Method)> = None;
        let mut current = Some(self.class(rt)?);
        while let Some(class) = current {
            for method in class.methods(rt)? {
                if method.name(rt)? != name || method.param_count(rt)? as usize != specs.len() {
                    continue;
                }
                let Some(score) = score_overload(rt, &method, specs)? else {
                    continue;
                };
                if score == specs.len() as i32 * 2 {
                    return Ok(method);
                }
                if best.as_ref().is_none_or(|(previous, _)| score > *previous) {
                    best = Some((score, method));
                }
            }
            current = class.parent(rt)?;
        }
        best.map(|(_, method)| method)
            .ok_or_else(|| Error::NotFound(format!("overloaded method {name}")))
    }

    /// `MakeGenericMethod` for this method.
    pub fn inflate(&self, rt: &mut Runtime, arguments: &[Class]) -> Result<Method> {
        let owner = if self.is_generic(rt)? {
            *self
        } else {
            self.class(rt)?
                .methods(rt)?
                .into_iter()
                .find(|method| {
                    method.name(rt).ok().as_deref() == self.name(rt).ok().as_deref()
                        && method.is_generic(rt).unwrap_or(false)
                })
                .ok_or_else(|| {
                    Error::Parse(format!(
                        "could not find inflatable signature of method {} with {} generic parameter(s)",
                        self.name(rt).unwrap_or_default(),
                        arguments.len()
                    ))
                })?
        };
        let reflected = rt
            .exports
            .call(rt.exports.method_get_object, &[owner.0, 0])?;
        let made = make_generic(rt, reflected, "MakeGenericMethod", arguments)?;
        let handle = object_field_pointer(rt, made, "mhandle")?;
        Ok(Method(handle))
    }
}

impl Class {
    /// `MakeGenericType` for this generic class.
    pub fn inflate(&self, rt: &mut Runtime, arguments: &[Class]) -> Result<Class> {
        if !self.is_generic(rt)? {
            return Err(Error::Parse(format!(
                "cannot inflate class {} as it has no generic parameters",
                self.full_name(rt)?
            )));
        }
        let type_object = type_object(rt, class_type(rt, *self)?)?;
        let made = make_generic(rt, type_object, "MakeGenericType", arguments)?;
        let class = rt
            .exports
            .call(rt.exports.class_from_system_type, &[made])?;
        Ok(Class(class))
    }
}

impl Runtime {
    /// Unbox a boxed value type. Reference types produce the same error text
    /// as the TypeScript bridge.
    pub fn unbox(&self, object: u64) -> Result<u64> {
        let class = self.object_class(object)?;
        if !class.is_value_type(self)? {
            return Err(Error::Parse(format!(
                "couldn't unbox instances of {} as they are not value types",
                class.full_name(self)?
            )));
        }
        self.exports.call(self.exports.object_unbox, &[object])
    }

    /// `UnityEngine.Application` string, or `None` when the call is absent.
    pub fn application_string(&self, method: &str) -> Result<Option<String>> {
        let icall_name = format!("UnityEngine.Application::{method}");
        let icall = self.resolve_icall(&icall_name).unwrap_or(0);
        if icall != 0 {
            let value = crate::ffi::call_ptr(icall as usize, &[])?;
            if value == 0 {
                return Ok(None);
            }
            return Ok(Some(self.string_utf16(value)?));
        }
        let Some(assembly) = self
            .domain()?
            .try_assembly(self, "UnityEngine.CoreModule")?
        else {
            return Ok(None);
        };
        let Some(class) = assembly
            .image(self)?
            .try_class(self, "UnityEngine.Application")?
        else {
            return Ok(None);
        };
        let Some(method) = class
            .methods(self)?
            .into_iter()
            .find(|item| item.name(self).ok().as_deref() == Some(method))
        else {
            return Ok(None);
        };
        let mut runtime = self.clone_shallow();
        let value = method.invoke_raw(&mut runtime, 0, &[])?;
        if value == 0 {
            return Ok(None);
        }
        Ok(Some(self.string_utf16(value)?))
    }

    /// Heap objects of `class`, via the liveness API. Missing exports are an
    /// error; the older `stopWorld` fallback deadlocks the script thread.
    pub fn choose(&self, class: Class) -> Result<Vec<u64>> {
        if self.exports.liveness_begin == 0 {
            return Err(Error::NotFound(
                "il2cpp_unity_liveness_calculation_begin".into(),
            ));
        }
        let mut found = Vec::new();
        let state = self.exports.call(
            self.exports.liveness_begin,
            &[
                class.0,
                0,
                choose_callback as *const () as usize as u64,
                &mut found as *mut Vec<u64> as u64,
                choose_noop as *const () as usize as u64,
                choose_noop as *const () as usize as u64,
            ],
        )?;
        self.exports
            .call(self.exports.liveness_from_statics, &[state])?;
        self.exports.call(self.exports.liveness_end, &[state])?;
        Ok(found)
    }
}

fn score_overload(rt: &Runtime, method: &Method, specs: &[OverloadSpec]) -> Result<Option<i32>> {
    let mut score = 0;
    for (index, spec) in specs.iter().enumerate() {
        let parameter = method.param_type(rt, index as u32)?;
        let parameter_class = parameter.class(rt)?;
        match spec {
            OverloadSpec::Name(name) => {
                if &parameter.name(rt)? == name {
                    score += 2;
                } else {
                    return Ok(None);
                }
            }
            OverloadSpec::Class(desired) => {
                if parameter_class.0 == desired.0 || parameter.name(rt)? == desired.full_name(rt)? {
                    score += 2;
                } else if parameter_class.is_assignable_from(rt, *desired)? {
                    score += 1;
                } else {
                    return Ok(None);
                }
            }
        }
    }
    Ok(Some(score))
}

fn class_type(rt: &Runtime, class: Class) -> Result<Type> {
    Ok(Type(
        rt.exports.call(rt.exports.class_get_type, &[class.0])?,
    ))
}

fn type_object(rt: &Runtime, ty: Type) -> Result<u64> {
    rt.exports.call(rt.exports.type_get_object, &[ty.0])
}

fn make_generic(
    rt: &mut Runtime,
    receiver: u64,
    method_name: &str,
    arguments: &[Class],
) -> Result<u64> {
    let owner = rt.object_class(receiver)?;
    let method = owner.method(rt, method_name, 1)?;
    let type_class = rt.corlib()?.class(rt, "System.Type")?;
    let type_objects: Vec<u64> = arguments
        .iter()
        .map(|class| type_object(rt, class_type(rt, *class)?))
        .collect::<Result<_>>()?;
    let array = array_of(rt, type_class, &type_objects)?;
    method.invoke_raw(rt, receiver, &[array])
}

fn array_of(rt: &Runtime, element: Class, items: &[u64]) -> Result<u64> {
    let array = rt.array_new(element, items.len() as u64)?;
    let base = array + 32;
    for (index, item) in items.iter().enumerate() {
        mem::write_u64(base + index as u64 * 8, *item)?;
    }
    Ok(array)
}

fn object_field_pointer(rt: &Runtime, object: u64, name: &str) -> Result<u64> {
    let class = rt.object_class(object)?;
    let field = class.field(rt, name)?;
    let offset = field.offset(rt)?;
    mem::read_u64(object.wrapping_add(offset as u64))
}

unsafe extern "C" fn choose_callback(
    objects: *const u64,
    size: i32,
    userdata: *mut core::ffi::c_void,
) {
    if objects.is_null() || userdata.is_null() || size <= 0 {
        return;
    }
    // SAFETY: `userdata` is the `Vec` passed to `liveness_begin` and the
    // callback runs before that `Vec` is dropped.
    let found = unsafe { &mut *userdata.cast::<Vec<u64>>() };
    for index in 0..size as usize {
        found.push(unsafe { *objects.add(index) });
    }
}

unsafe extern "C" fn choose_noop() {}
