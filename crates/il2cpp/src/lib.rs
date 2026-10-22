//! IL2CPP runtime bridge.
//!
//! Port of [frida-il2cpp-bridge](https://github.com/vfsfitvnm/frida-il2cpp-bridge):
//! resolve `il2cpp_*` in `libil2cpp.so`, walk the domain, and hook method bodies.
//! It does not parse `global-metadata.dat`. The script-facing object is `Il2Cpp`.

mod exports;
mod ffi;
mod mem;
mod runtime;
mod symbol;

#[cfg(target_os = "android")]
mod trace;

pub use runtime::{
    dump_assembly, dump_class, Assembly, Class, Domain, Field, Image, Method, Runtime, Type,
};

#[cfg(target_os = "android")]
pub use trace::trace_method;
pub use symbol::{find_unity_version, MODULE_NAMES};

use ::runtime::Result;
use serde_json::{json, Value};

/// Attach this thread and report what a script needs to see that IL2CPP is alive.
pub fn summary() -> Result<Value> {
    let mut rt = Runtime::attach()?;
    let assemblies = rt.domain()?.assemblies(&rt)?;
    let mut names = Vec::with_capacity(assemblies.len());
    for assembly in &assemblies {
        names.push(assembly.name(&rt)?);
    }
    let corlib = rt.corlib()?;
    let corlib_name = corlib.name(&rt)?;
    let corlib_classes = corlib.class_count(&rt)?;
    let string_class = corlib.class(&rt, "System.String")?;
    let string_methods = string_class.methods(&rt)?;
    let length_method = string_class.method(&mut rt, "get_Length", 0)?;
    let length_va = length_method.virtual_address(&mut rt)?;
    let sample = rt.new_string("mouse")?;
    let sample_len = rt.string_length(sample)?;
    let sample_text = rt.string_utf16(sample)?;
    let heap = rt.gc_heap_size().unwrap_or(0);
    let threads = rt.attached_threads().map(|threads| threads.len()).unwrap_or(0);
    let missing = rt.exports.missing().len();
    Ok(json!({
        "module": rt.module.name,
        "base": format!("{:#x}", rt.module.base),
        "unity": rt.unity_version(),
        "assemblies": names,
        "corlib": corlib_name,
        "corlibClasses": corlib_classes,
        "stringMethods": string_methods.len(),
        "getLength": format!("{length_va:#x}"),
        "sample": sample_text,
        "sampleLen": sample_len,
        "heap": heap,
        "threads": threads,
        "missingExports": missing,
    }))
}

#[cfg(test)]
mod tests {
    use super::find_unity_version;

    #[test]
    fn unity_version_from_banner() {
        let text = "junk Unity 2019.4.40f1 (abc) more 6000.0.23f1";
        assert_eq!(find_unity_version(text).as_deref(), Some("2019.4.40f1"));
    }

    #[test]
    fn unity_version_rejects_noise() {
        assert!(find_unity_version("1.2.3f4 no").is_none());
    }
}
