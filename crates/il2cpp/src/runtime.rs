//! IL2CPP object model: domain, image, class, method, field, string, thread, GC.
//!
//! Handles are native pointers. Names and lists are resolved through
//! [`crate::exports::Exports`] on each call so a class initialized later is visible.

use std::cell::RefCell;
use std::collections::HashMap;

use crate::exports::{self, Exports};
use crate::mem;
use runtime::module::Module;
use runtime::{Error, Result};

const FIELD_STATIC: i32 = 0x0010;
const FIELD_LITERAL: i32 = 0x0040;
const METHOD_STATIC: u32 = 0x0010;

thread_local! {
    static CURRENT: RefCell<Option<Runtime>> = const { RefCell::new(None) };
}

/// One attached IL2CPP session on this thread.
pub struct Runtime {
    pub module: Module,
    pub exports: Exports,
    thread: u64,
    method_pointer_offset: Option<u64>,
}

impl Runtime {
    /// Find `libil2cpp.so`, attach this thread to the domain, and keep the session.
    pub fn attach() -> Result<Runtime> {
        let (module, exports) = wait_until_loaded()?;
        let mut domain = 0;
        for _ in 0..8 {
            domain = exports.call(exports.domain_get, &[])?;
            let corlib = exports.call(exports.get_corlib, &[])?;
            if domain != 0 && corlib != 0 {
                break;
            }
            std::thread::sleep(std::time::Duration::from_millis(250));
        }
        if domain == 0 {
            return Err(Error::Parse(
                "il2cpp_domain_get returned NULL; il2cpp_init has not finished".into(),
            ));
        }
        let thread = exports.call(exports.thread_attach, &[domain])?;
        if thread == 0 {
            return Err(Error::Parse("il2cpp_thread_attach returned NULL".into()));
        }
        let runtime = Runtime {
            module,
            exports,
            thread,
            method_pointer_offset: None,
        };
        CURRENT.with(|slot| *slot.borrow_mut() = Some(runtime.clone_shallow()));
        Ok(runtime)
    }

    pub(crate) fn clone_shallow(&self) -> Runtime {
        Runtime {
            module: self.module.clone(),
            exports: self.exports.clone(),
            thread: self.thread,
            method_pointer_offset: self.method_pointer_offset,
        }
    }

    pub fn current() -> Result<Runtime> {
        CURRENT.with(|slot| {
            slot.borrow()
                .as_ref()
                .map(Runtime::clone_shallow)
                .ok_or_else(|| Error::Parse("Il2Cpp.attach has not run on this thread".into()))
        })
    }

    /// The session on this thread, attaching on first use.
    pub fn session() -> Result<Runtime> {
        if let Ok(runtime) = Self::current() {
            return Ok(runtime);
        }
        Self::attach()
    }

    pub fn domain(&self) -> Result<Domain> {
        Ok(Domain(self.exports.call(self.exports.domain_get, &[])?))
    }

    pub fn corlib(&self) -> Result<Image> {
        Ok(Image(self.exports.call(self.exports.get_corlib, &[])?))
    }

    pub fn unity_version(&self) -> Option<String> {
        crate::symbol::unity_version(&self.module)
    }

    pub fn new_string(&self, text: &str) -> Result<u64> {
        let c = mem::cstring(text)?;
        self.exports
            .call(self.exports.string_new, &[c.as_ptr() as u64])
    }

    pub fn string_length(&self, string: u64) -> Result<i32> {
        Ok(self.exports.call(self.exports.string_length, &[string])? as i32)
    }

    pub fn string_utf16(&self, string: u64) -> Result<String> {
        let length = self.string_length(string)? as u64;
        let chars = self.exports.call(self.exports.string_chars, &[string])?;
        if chars == 0 {
            return Ok(String::new());
        }
        let mut units = Vec::with_capacity(length as usize);
        for index in 0..length {
            let unit = mem::read_u64(chars + index * 2)? as u16;
            // read_u64 would over-read. Read two bytes.
            let lo = mem::read_u8(chars + index * 2)?;
            let hi = mem::read_u8(chars + index * 2 + 1)?;
            units.push(u16::from_le_bytes([lo, hi]));
            let _ = unit;
        }
        Ok(String::from_utf16_lossy(&units))
    }

    pub fn gc_heap_size(&self) -> Result<u64> {
        self.exports.call(self.exports.gc_get_heap_size, &[])
    }

    pub fn gc_used_size(&self) -> Result<u64> {
        self.exports.call(self.exports.gc_get_used_size, &[])
    }

    pub fn attached_threads(&self) -> Result<Vec<u64>> {
        let mut count = 0u64;
        let start = self
            .exports
            .call(self.exports.thread_get_all_attached, [&mut count as *mut u64 as u64].as_slice())?;
        read_pointer_list(start, count)
    }

    pub fn object_class(&self, object: u64) -> Result<Class> {
        Ok(Class(self.exports.call(self.exports.object_get_class, &[object])?))
    }

    pub fn object_size(&self, object: u64) -> Result<u32> {
        Ok(self.exports.call(self.exports.object_get_size, &[object])? as u32)
    }

    pub fn array_length(&self, array: u64) -> Result<u32> {
        Ok(self.exports.call(self.exports.array_length, &[array])? as u32)
    }

    pub fn array_new(&self, class: Class, length: u64) -> Result<u64> {
        self.exports.call(self.exports.array_new, &[class.0, length])
    }

    pub fn gc_collect(&self, generation: i32) -> Result<()> {
        self.exports.call(self.exports.gc_collect, &[generation as u64])?;
        Ok(())
    }

    pub fn thread_current(&self) -> Result<u64> {
        self.exports.call(self.exports.thread_current, &[])
    }

    pub fn thread_detach(&self, thread: u64) -> Result<()> {
        self.exports.call(self.exports.thread_detach, &[thread])?;
        Ok(())
    }

    pub fn resolve_icall(&self, name: &str) -> Result<u64> {
        let c = mem::cstring(name)?;
        self.exports
            .call(self.exports.resolve_icall, &[c.as_ptr() as u64])
    }

    pub fn method_pointer_offset(&mut self) -> Result<u64> {
        if let Some(offset) = self.method_pointer_offset {
            return Ok(offset);
        }
        let class = self.corlib()?.class(self, "System.String")?;
        let method = class.method(self, "get_Length", 0)?;
        let offset = probe_method_pointer(&self.module, method.0)?;
        self.method_pointer_offset = Some(offset);
        CURRENT.with(|slot| {
            if let Some(current) = slot.borrow_mut().as_mut() {
                current.method_pointer_offset = Some(offset);
            }
        });
        Ok(offset)
    }

    pub fn class_init(&self, class: u64) -> Result<()> {
        if self.exports.runtime_class_init == 0 {
            return Ok(());
        }
        self.exports.call(self.exports.runtime_class_init, &[class])?;
        Ok(())
    }
}

#[derive(Clone, Copy)]
pub struct Domain(pub u64);

impl Domain {
    pub fn assemblies(&self, rt: &Runtime) -> Result<Vec<Assembly>> {
        let mut count = 0usize;
        let start = rt.exports.call(
            rt.exports.domain_get_assemblies,
            &[self.0, &mut count as *mut usize as u64],
        )?;
        Ok(read_pointer_list(start, count as u64)?
            .into_iter()
            .map(Assembly)
            .collect())
    }

    pub fn assembly(&self, rt: &Runtime, name: &str) -> Result<Assembly> {
        self.try_assembly(rt, name)?
            .ok_or_else(|| Error::NotFound(format!("assembly {name}")))
    }

    pub fn try_assembly(&self, rt: &Runtime, name: &str) -> Result<Option<Assembly>> {
        let c = mem::cstring(name)?;
        let handle = rt.exports.call(
            rt.exports.domain_assembly_open,
            &[self.0, c.as_ptr() as u64],
        )?;
        Ok((handle != 0).then_some(Assembly(handle)))
    }
}

#[derive(Clone, Copy)]
pub struct Assembly(pub u64);

impl Assembly {
    pub fn image(&self, rt: &Runtime) -> Result<Image> {
        Ok(Image(rt.exports.call(rt.exports.assembly_get_image, &[self.0])?))
    }

    pub fn name(&self, rt: &Runtime) -> Result<String> {
        let name = self.image(rt)?.name(rt)?;
        Ok(name.strip_suffix(".dll").unwrap_or(&name).to_owned())
    }
}

#[derive(Clone, Copy)]
pub struct Image(pub u64);

impl Image {
    pub fn name(&self, rt: &Runtime) -> Result<String> {
        let ptr = rt.exports.call(rt.exports.image_get_name, &[self.0])?;
        mem::cstr(ptr)
    }

    pub fn class_count(&self, rt: &Runtime) -> Result<u32> {
        Ok(rt.exports.call(rt.exports.image_get_class_count, &[self.0])? as u32)
    }

    pub fn class_at(&self, rt: &Runtime, index: u32) -> Result<Class> {
        Ok(Class(rt.exports.call(rt.exports.image_get_class, &[self.0, index as u64])?))
    }

    pub fn classes(&self, rt: &Runtime) -> Result<Vec<Class>> {
        let count = self.class_count(rt)?;
        let mut out = Vec::with_capacity(count as usize);
        for index in 0..count {
            let class = self.class_at(rt, index)?;
            if class.0 != 0 {
                out.push(class);
            }
        }
        Ok(out)
    }

    pub fn class(&self, rt: &Runtime, full_name: &str) -> Result<Class> {
        let image = self.name(rt)?;
        self.try_class(rt, full_name)?
            .ok_or_else(|| Error::NotFound(format!("class {full_name} in {image}")))
    }

    pub fn try_class(&self, rt: &Runtime, full_name: &str) -> Result<Option<Class>> {
        let (namespace, name) = split_name(full_name);
        let namespace = mem::cstring(&namespace)?;
        let name = mem::cstring(&name)?;
        let handle = rt.exports.call(
            rt.exports.class_from_name,
            &[self.0, namespace.as_ptr() as u64, name.as_ptr() as u64],
        )?;
        Ok((handle != 0).then_some(Class(handle)))
    }
}

#[derive(Clone, Copy)]
pub struct Class(pub u64);

impl Class {
    pub fn name(&self, rt: &Runtime) -> Result<String> {
        mem::cstr(rt.exports.call(rt.exports.class_get_name, &[self.0])?)
    }

    pub fn namespace(&self, rt: &Runtime) -> Result<String> {
        mem::cstr(rt.exports.call(rt.exports.class_get_namespace, &[self.0])?)
    }

    pub fn full_name(&self, rt: &Runtime) -> Result<String> {
        let namespace = self.namespace(rt)?;
        let name = self.name(rt)?;
        if namespace.is_empty() {
            Ok(name)
        } else {
            Ok(format!("{namespace}.{name}"))
        }
    }

    pub fn parent(&self, rt: &Runtime) -> Result<Option<Class>> {
        let handle = rt.exports.call(rt.exports.class_get_parent, &[self.0])?;
        Ok((handle != 0).then_some(Class(handle)))
    }

    pub fn is_enum(&self, rt: &Runtime) -> Result<bool> {
        Ok(rt.exports.call(rt.exports.class_is_enum, &[self.0])? != 0)
    }

    pub fn is_value_type(&self, rt: &Runtime) -> Result<bool> {
        Ok(rt.exports.call(rt.exports.class_is_valuetype, &[self.0])? != 0)
    }

    pub fn is_interface(&self, rt: &Runtime) -> Result<bool> {
        Ok(rt.exports.call(rt.exports.class_is_interface, &[self.0])? != 0)
    }

    pub fn instance_size(&self, rt: &Runtime) -> Result<i32> {
        Ok(rt.exports.call(rt.exports.class_instance_size, &[self.0])? as i32)
    }

    pub fn flags(&self, rt: &Runtime) -> Result<i32> {
        Ok(rt.exports.call(rt.exports.class_get_flags, &[self.0])? as i32)
    }

    pub fn methods(&self, rt: &Runtime) -> Result<Vec<Method>> {
        Ok(native_iterator(|iter| rt.exports.call(rt.exports.class_get_methods, &[self.0, iter]))?
            .into_iter()
            .map(Method)
            .collect())
    }

    pub fn fields(&self, rt: &Runtime) -> Result<Vec<Field>> {
        Ok(native_iterator(|iter| rt.exports.call(rt.exports.class_get_fields, &[self.0, iter]))?
            .into_iter()
            .map(Field)
            .collect())
    }

    pub fn nested(&self, rt: &Runtime) -> Result<Vec<Class>> {
        Ok(
            native_iterator(|iter| rt.exports.call(rt.exports.class_get_nested_types, &[self.0, iter]))?
                .into_iter()
                .map(Class)
                .collect(),
        )
    }

    pub fn method(&self, rt: &Runtime, name: &str, argc: i32) -> Result<Method> {
        let c = mem::cstring(name)?;
        let handle = rt.exports.call(
            rt.exports.class_get_method_from_name,
            &[self.0, c.as_ptr() as u64, argc as u64],
        )?;
        if handle == 0 {
            return Err(Error::NotFound(format!("method {name}/{argc}")));
        }
        Ok(Method(handle))
    }

    pub fn field(&self, rt: &Runtime, name: &str) -> Result<Field> {
        let c = mem::cstring(name)?;
        let handle = rt.exports.call(
            rt.exports.class_get_field_from_name,
            &[self.0, c.as_ptr() as u64],
        )?;
        if handle == 0 {
            return Err(Error::NotFound(format!("field {name}")));
        }
        Ok(Field(handle))
    }

    pub fn is_abstract(&self, rt: &Runtime) -> Result<bool> {
        Ok(rt.exports.call(rt.exports.class_is_abstract, &[self.0])? != 0)
    }

    pub fn is_generic(&self, rt: &Runtime) -> Result<bool> {
        Ok(rt.exports.call(rt.exports.class_is_generic, &[self.0])? != 0)
    }

    pub fn is_inflated(&self, rt: &Runtime) -> Result<bool> {
        Ok(rt.exports.call(rt.exports.class_is_inflated, &[self.0])? != 0)
    }

    pub fn is_assignable_from(&self, rt: &Runtime, other: Class) -> Result<bool> {
        Ok(rt.exports.call(rt.exports.class_is_assignable_from, &[self.0, other.0])? != 0)
    }

    pub fn is_subclass_of(&self, rt: &Runtime, other: Class, check_interfaces: bool) -> Result<bool> {
        Ok(rt.exports.call(
            rt.exports.class_is_subclass_of,
            &[self.0, other.0, u64::from(check_interfaces)],
        )? != 0)
    }

    pub fn alloc(&self, rt: &Runtime) -> Result<u64> {
        rt.exports.call(rt.exports.alloc, &[self.instance_size(rt)? as u64])
    }

    pub fn new_object(&self, rt: &Runtime) -> Result<u64> {
        rt.class_init(self.0)?;
        let object = rt.exports.call(rt.exports.object_new, &[self.0])?;
        if object != 0 && rt.exports.object_init != 0 {
            let _ = rt.exports.call(rt.exports.object_init, &[object]);
        }
        Ok(object)
    }

    pub fn array_class(&self, rt: &Runtime) -> Result<Class> {
        Ok(Class(rt.exports.call(rt.exports.array_class_get, &[self.0, 1])?))
    }

    pub fn kind(&self, rt: &Runtime) -> Result<&'static str> {
        if self.is_enum(rt)? {
            Ok("enum")
        } else if self.is_value_type(rt)? {
            Ok("struct")
        } else if self.is_interface(rt)? {
            Ok("interface")
        } else {
            Ok("class")
        }
    }
}

#[derive(Clone, Copy)]
pub struct Method(pub u64);

impl Method {
    pub fn name(&self, rt: &Runtime) -> Result<String> {
        mem::cstr(rt.exports.call(rt.exports.method_get_name, &[self.0])?)
    }

    pub fn class(&self, rt: &Runtime) -> Result<Class> {
        Ok(Class(rt.exports.call(rt.exports.method_get_class, &[self.0])?))
    }

    pub fn param_count(&self, rt: &Runtime) -> Result<u32> {
        Ok(rt.exports.call(rt.exports.method_get_param_count, &[self.0])? as u32)
    }

    pub fn param_name(&self, rt: &Runtime, index: u32) -> Result<String> {
        mem::cstr(rt.exports.call(rt.exports.method_get_param_name, &[self.0, index as u64])?)
    }

    pub fn param_type(&self, rt: &Runtime, index: u32) -> Result<Type> {
        Ok(Type(rt.exports.call(rt.exports.method_get_param, &[self.0, index as u64])?))
    }

    pub fn is_generic(&self, rt: &Runtime) -> Result<bool> {
        Ok(rt.exports.call(rt.exports.method_is_generic, &[self.0])? != 0)
    }

    pub fn is_inflated(&self, rt: &Runtime) -> Result<bool> {
        Ok(rt.exports.call(rt.exports.method_is_inflated, &[self.0])? != 0)
    }

    pub fn is_instance(&self, rt: &Runtime) -> Result<bool> {
        Ok(rt.exports.call(rt.exports.method_is_instance, &[self.0])? != 0)
    }

    pub fn return_type(&self, rt: &Runtime) -> Result<Type> {
        Ok(Type(rt.exports.call(rt.exports.method_get_return_type, &[self.0])?))
    }

    pub fn flags(&self, rt: &Runtime) -> Result<u32> {
        let mut impl_flags = 0u32;
        let flags = rt.exports.call(
            rt.exports.method_get_flags,
            &[self.0, &mut impl_flags as *mut u32 as u64],
        )?;
        Ok(flags as u32)
    }

    pub fn is_static(&self, rt: &Runtime) -> Result<bool> {
        Ok(self.flags(rt)? & METHOD_STATIC != 0)
    }

    pub fn virtual_address(&self, rt: &mut Runtime) -> Result<u64> {
        let offset = rt.method_pointer_offset()?;
        mem::read_u64(self.0 + offset)
    }

    /// Invoke a method whose arguments and return value are raw register values.
    pub fn invoke_raw(&self, rt: &mut Runtime, instance: u64, args: &[u64]) -> Result<u64> {
        let address = self.virtual_address(rt)?;
        if address == 0 {
            return Err(Error::Parse(format!("method {} has a null virtual address", self.name(rt)?)));
        }
        let mut gpr = Vec::with_capacity(args.len() + 1);
        if !self.is_static(rt)? {
            gpr.push(instance);
        }
        gpr.extend_from_slice(args);
        ffi_call(address as usize, &gpr)
    }

    pub fn signature(&self, rt: &Runtime) -> Result<String> {
        let ret = self.return_type(rt)?.name(rt)?;
        let mut params = Vec::new();
        for index in 0..self.param_count(rt)? {
            params.push(self.param_name(rt, index)?);
        }
        Ok(format!("{ret} {}({})", self.name(rt)?, params.join(", ")))
    }
}

#[derive(Clone, Copy)]
pub struct Field(pub u64);

impl Field {
    pub fn name(&self, rt: &Runtime) -> Result<String> {
        mem::cstr(rt.exports.call(rt.exports.field_get_name, &[self.0])?)
    }

    pub fn offset(&self, rt: &Runtime) -> Result<i32> {
        Ok(rt.exports.call(rt.exports.field_get_offset, &[self.0])? as i32)
    }

    pub fn flags(&self, rt: &Runtime) -> Result<i32> {
        Ok(rt.exports.call(rt.exports.field_get_flags, &[self.0])? as i32)
    }

    pub fn is_static(&self, rt: &Runtime) -> Result<bool> {
        Ok(self.flags(rt)? & FIELD_STATIC != 0)
    }

    pub fn is_literal(&self, rt: &Runtime) -> Result<bool> {
        Ok(self.flags(rt)? & FIELD_LITERAL != 0)
    }

    pub fn type_(&self, rt: &Runtime) -> Result<Type> {
        Ok(Type(rt.exports.call(rt.exports.field_get_type, &[self.0])?))
    }

    pub fn static_pointer(&self, rt: &Runtime) -> Result<u64> {
        let mut slot = 0u64;
        rt.exports
            .call(rt.exports.field_static_get_value, &[self.0, &mut slot as *mut u64 as u64])?;
        Ok(slot)
    }

    pub fn instance_u64(&self, rt: &Runtime, object: u64) -> Result<u64> {
        let offset = self.offset(rt)?;
        mem::read_u64(object.wrapping_add(offset as u64))
    }
}

#[derive(Clone, Copy)]
pub struct Type(pub u64);

impl Type {
    pub fn name(&self, rt: &Runtime) -> Result<String> {
        let ptr = rt.exports.call(rt.exports.type_get_name, &[self.0])?;
        let name = mem::cstr(ptr)?;
        if ptr != 0 && rt.exports.free != 0 {
            let _ = rt.exports.call(rt.exports.free, &[ptr]);
        }
        Ok(name)
    }

    pub fn enum_value(&self, rt: &Runtime) -> Result<i32> {
        Ok(rt.exports.call(rt.exports.type_get_type, &[self.0])? as i32)
    }

    pub fn class(&self, rt: &Runtime) -> Result<Class> {
        Ok(Class(rt.exports.call(rt.exports.class_from_type, &[self.0])?))
    }
}

pub fn native_iterator(mut step: impl FnMut(u64) -> Result<u64>) -> Result<Vec<u64>> {
    let mut iter = 0u64;
    let mut out = Vec::new();
    loop {
        let handle = step(&mut iter as *mut u64 as u64)?;
        if handle == 0 {
            break;
        }
        out.push(handle);
        if out.len() > 100_000 {
            return Err(Error::Parse("il2cpp iterator exceeded 100000 entries".into()));
        }
    }
    Ok(out)
}

fn read_pointer_list(start: u64, count: u64) -> Result<Vec<u64>> {
    if start == 0 || count == 0 {
        return Ok(Vec::new());
    }
    let mut out = Vec::with_capacity(count as usize);
    for index in 0..count {
        out.push(mem::read_u64(start + index * 8)?);
    }
    Ok(out)
}

fn split_name(full_name: &str) -> (String, String) {
    match full_name.rfind('.') {
        Some(index) => (full_name[..index].to_owned(), full_name[index + 1..].to_owned()),
        None => (String::new(), full_name.to_owned()),
    }
}

fn probe_method_pointer(module: &Module, method_info: u64) -> Result<u64> {
    for offset in (0..0x48).step_by(8) {
        let pointer = mem::read_u64(method_info + offset)?;
        if pointer != 0 && in_module_exec(module, pointer) {
            return Ok(offset);
        }
    }
    Err(Error::Parse(
        "could not find MethodInfo.methodPointer inside libil2cpp".into(),
    ))
}

fn in_module_exec(module: &Module, addr: u64) -> bool {
    module.contains(addr as usize) && mem::is_executable(addr)
}

fn wait_until_loaded() -> Result<(Module, Exports)> {
    let mut last = Error::NotFound("libil2cpp.so".into());
    for _ in 0..8 {
        match exports::load(&HashMap::new()) {
            Ok(loaded) => return Ok(loaded),
            Err(err) => last = err,
        }
        std::thread::sleep(std::time::Duration::from_millis(250));
    }
    Err(last)
}

fn ffi_call(target: usize, args: &[u64]) -> Result<u64> {
    crate::ffi::call_ptr(target, args)
}

/// Text dump of one class: kind, parent, fields, methods. This is the record
/// the upstream dump agent sends for each class.
pub fn dump_class(rt: &Runtime, class: Class) -> Result<String> {
    let parent = class
        .parent(rt)?
        .map(|parent| parent.full_name(rt))
        .transpose()?
        .unwrap_or_default();
    let mut text = format!(
        "{} {} : {parent}\n",
        class.kind(rt)?,
        class.full_name(rt)?
    );
    for field in class.fields(rt)? {
        let static_ = if field.is_static(rt)? { "static " } else { "" };
        text.push_str(&format!(
            "  {static_}{} {} // {:#x}\n",
            field.type_(rt)?.name(rt)?,
            field.name(rt)?,
            field.offset(rt)?
        ));
    }
    for method in class.methods(rt)? {
        text.push_str("  ");
        text.push_str(&method.signature(rt)?);
        text.push('\n');
    }
    Ok(text)
}

/// Walk every class in `assembly` (or corlib when `None`). `limit` stops early.
pub fn dump_assembly(rt: &Runtime, assembly: Option<&str>, limit: Option<usize>) -> Result<String> {
    let image = match assembly {
        Some(name) => rt.domain()?.assembly(rt, name)?.image(rt)?,
        None => rt.corlib()?,
    };
    let classes = image.classes(rt)?;
    let total = classes.len();
    let take = limit.unwrap_or(total).min(total);
    let mut text = format!("// {} classes, showing {take}\n", image.name(rt)?);
    for class in classes.into_iter().take(take) {
        text.push_str(&dump_class(rt, class)?);
        text.push('\n');
    }
    let _ = total;
    Ok(text)
}
