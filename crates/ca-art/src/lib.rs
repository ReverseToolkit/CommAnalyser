//! ART/JNI foundation for CommAnalyser.
//!
//! M3a only probes the running ART: discover the JavaVM, obtain a
//! `jmethodID` (= `ArtMethod*` on ART), and inspect the first cache line for
//! candidate entrypoint offsets.  Patching/deoptimization builds on this.

use std::ffi::c_void;
use std::ptr;

use jni::objects::{JObject, JValue};
use jni::signature::RuntimeMethodSignature;
use jni::strings::JNIString;
use jni::sys::{jint, jsize, JavaVM as RawJavaVM};
use jni::JavaVM;

use ca_core::{maps, Error, Result};

type GetCreatedJavaVms = unsafe extern "C" fn(*mut *mut RawJavaVM, jsize, *mut jsize) -> jint;

/// Probe the ART currently loaded in this process.
pub fn probe() -> Result<String> {
    let raw_vm = created_java_vm()?;
    // SAFETY: JNI_GetCreatedJavaVMs returned a live JavaVM.
    let vm = unsafe { JavaVM::from_raw(raw_vm) };

    vm.attach_current_thread(|env| -> jni::errors::Result<String> {
        let class_name = JNIString::new("java/lang/StringBuilder");
        let class = env.find_class(&*class_name)?;

        let ctor_sig = RuntimeMethodSignature::from_str("()V")?;
        let object = env.new_object(&class, ctor_sig.method_signature(), &[])?;

        let text = env.new_string("hello")?;
        let text = JObject::from(text);
        let append_name = JNIString::new("append");
        let append_sig =
            RuntimeMethodSignature::from_str("(Ljava/lang/String;)Ljava/lang/StringBuilder;")?;
        env.call_method(
            &object,
            &*append_name,
            append_sig.method_signature(),
            &[JValue::Object(&text)],
        )?;

        let length_name = JNIString::new("length");
        let length_sig = RuntimeMethodSignature::from_str("()I")?;
        let length_id = env.get_method_id(&class, &*length_name, length_sig.method_signature())?;
        let length = env
            .call_method(&object, &*length_name, length_sig.method_signature(), &[])?
            .i()?;

        let art_method = length_id.into_raw() as *mut u8;
        let candidates = scan_art_method(art_method);
        Ok(serde_json::json!({
            "ok": true,
            "length": length,
            "art_method": format!("{art_method:p}"),
            "candidates": candidates,
        })
        .to_string())
    })
    .map_err(|err| Error::Parse(format!("JNI: {err}")))
}

fn created_java_vm() -> Result<*mut RawJavaVM> {
    // SAFETY: dlsym returns the JNI entrypoint exported by libart.
    let symbol = unsafe { libc::dlsym(libc::RTLD_DEFAULT, c"JNI_GetCreatedJavaVMs".as_ptr()) };
    if symbol.is_null() {
        return Err(Error::NotFound("JNI_GetCreatedJavaVMs".into()));
    }
    // SAFETY: signature matches JNIInvokeInterface.
    let get: GetCreatedJavaVms = unsafe { std::mem::transmute(symbol) };
    let mut vm: *mut RawJavaVM = ptr::null_mut();
    let mut count: jsize = 0;
    // SAFETY: the pointee is a valid JavaVM slot and count slot.
    let rc = unsafe { get(&mut vm, 1, &mut count) };
    if rc != 0 || count == 0 || vm.is_null() {
        return Err(Error::NotFound("no created JavaVM".into()));
    }
    Ok(vm)
}

fn scan_art_method(art_method: *mut u8) -> Vec<serde_json::Value> {
    let Ok(exec_ranges) = executable_ranges() else {
        return Vec::new();
    };
    let mut out = Vec::new();
    for offset in (0..32).step_by(8) {
        // SAFETY: ArtMethod is at least a few pointer-sized fields; the caller
        // only runs inside a live ART process.
        let value = unsafe { ptr::read_unaligned(art_method.add(offset) as *const u64) };
        if value == 0 {
            continue;
        }
        let address = value as usize;
        if let Some((start, end)) = exec_ranges
            .iter()
            .copied()
            .find(|(start, end)| address >= *start && address < *end)
        {
            out.push(serde_json::json!({
                "offset": offset,
                "value": format!("{address:#x}"),
                "exec_range": format!("{start:#x}-{end:#x}"),
            }));
        }
    }
    out
}

fn executable_ranges() -> Result<Vec<(usize, usize)>> {
    let maps = maps::read_self_maps()?;
    Ok(maps
        .into_iter()
        .filter(|mapping| mapping.perms.exec)
        .map(|mapping| (mapping.range.start, mapping.range.end))
        .collect())
}

/// Helper for callers that need the libart load bias.
pub fn libart_base() -> Result<usize> {
    let maps = maps::read_self_maps()?;
    maps.iter()
        .find(|mapping| {
            mapping
                .clean_path()
                .is_some_and(|path| path.ends_with("/libart.so"))
        })
        .map(|mapping| mapping.range.start.saturating_sub(mapping.offset as usize))
        .ok_or_else(|| Error::NotFound("libart.so".into()))
}

/// Try patching each executable pointer candidate in the ArtMethod and see
/// which one is used by a JNI invocation of `StringBuilder.length`.
pub fn probe_hook() -> Result<String> {
    let raw_vm = created_java_vm()?;
    // SAFETY: JNI_GetCreatedJavaVMs returned a live JavaVM.
    let vm = unsafe { JavaVM::from_raw(raw_vm) };

    vm.attach_current_thread(|env| -> jni::errors::Result<String> {
        let class_name = JNIString::new("java/lang/StringBuilder");
        let class = env.find_class(&*class_name)?;
        let ctor_sig = RuntimeMethodSignature::from_str("()V")?;
        let object = env.new_object(&class, ctor_sig.method_signature(), &[])?;
        let length_name = JNIString::new("length");
        let length_sig = RuntimeMethodSignature::from_str("()I")?;
        let length_id = env.get_method_id(&class, &*length_name, length_sig.method_signature())?;
        let art_method = length_id.into_raw() as *mut u8;

        let stub = match hook_stub() {
            Ok(stub) => stub,
            Err(err) => {
                return Ok(serde_json::json!({
                    "ok": false,
                    "error": err.to_string(),
                })
                .to_string())
            }
        };
        let mut attempts = Vec::new();
        let mut candidates = scan_art_method(art_method);
        candidates
            .sort_by_key(|candidate| std::cmp::Reverse(candidate["offset"].as_u64().unwrap_or(0)));
        for candidate in candidates {
            let Some(offset) = candidate["offset"].as_u64().map(|value| value as usize) else {
                continue;
            };
            let address = art_method as usize + offset;
            let original = read_pointer(address);
            write_pointer(address, stub);
            let value = env
                .call_method(&object, &*length_name, length_sig.method_signature(), &[])
                .and_then(|value| value.i())
                .map(|value| value as u64)
                .unwrap_or(u64::MAX);
            write_pointer(address, original);
            attempts.push(serde_json::json!({
                "offset": offset,
                "original": format!("{original:#x}"),
                "value": value,
            }));
            if value == 0x1234 {
                break;
            }
        }
        Ok(serde_json::json!({
            "ok": true,
            "art_method": format!("{art_method:p}"),
            "attempts": attempts,
        })
        .to_string())
    })
    .map_err(|err| Error::Parse(format!("JNI: {err}")))
}

fn hook_stub() -> Result<usize> {
    static STUB: std::sync::OnceLock<usize> = std::sync::OnceLock::new();
    let address = *STUB.get_or_init(|| make_hook_stub().unwrap_or(0));
    if address == 0 {
        return Err(Error::Unsupported("ART hook stub allocation failed"));
    }
    Ok(address)
}

fn make_hook_stub() -> Option<usize> {
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
        return None;
    }
    // bti c ; mov w0, #0x1234 ; ret
    let code: [u32; 3] = [0xD503_24DF, 0x5282_4680, 0xD65F_03C0];
    unsafe {
        ptr::copy_nonoverlapping(code.as_ptr() as *const u8, page as *mut u8, 12);
        // Leave the page RWX: Android's execmem policy can reject a later
        // mprotect(RX) even though the anonymous mmap succeeded.
    }
    Some(page as usize)
}

fn read_pointer(address: usize) -> usize {
    unsafe { ptr::read_unaligned(address as *const usize) }
}

fn write_pointer(address: usize, value: usize) {
    let page_size = ca_core::process::page_size();
    let page = address & !(page_size - 1);
    unsafe {
        libc::mprotect(
            page as *mut c_void,
            page_size,
            libc::PROT_READ | libc::PROT_WRITE,
        );
        ptr::write_unaligned(address as *mut usize, value);
        libc::mprotect(
            page as *mut c_void,
            page_size,
            libc::PROT_READ | libc::PROT_EXEC,
        );
    }
    ca_gum_flush(address, std::mem::size_of::<usize>());
}

fn ca_gum_flush(address: usize, len: usize) {
    // Keep ca-art independent of ca-gum: use the same cache-maintenance
    // sequence locally.
    #[cfg(not(target_arch = "aarch64"))]
    {
        let _ = (address, len);
    }
    #[cfg(target_arch = "aarch64")]
    {
        let start = address & !63;
        let end = (address + len + 63) & !63;
        let mut line = start;
        while line < end {
            unsafe {
                core::arch::asm!("dc cvau, {}", in(reg) line, options(nostack, preserves_flags));
            }
            line += 64;
        }
        unsafe {
            core::arch::asm!("dsb ish", options(nostack, preserves_flags));
        }
        let mut line = start;
        while line < end {
            unsafe {
                core::arch::asm!("ic ivau, {}", in(reg) line, options(nostack, preserves_flags));
            }
            line += 64;
        }
        unsafe {
            core::arch::asm!("dsb ish", "isb", options(nostack, preserves_flags));
        }
    }
}

/// Diagnostic: allocate the ART hook stub and report its mapping permissions.
pub fn stub_info() -> Result<String> {
    let stub = hook_stub()?;
    let maps = maps::read_self_maps()?;
    let mapping = maps.iter().find(|mapping| mapping.range.contains(stub));
    Ok(serde_json::json!({
        "ok": true,
        "stub": format!("{stub:#x}"),
        "perms": mapping.map(|m| format!("{:?}", m.perms)),
        "path": mapping.and_then(|m| m.path.clone()),
    })
    .to_string())
}

#[cfg(test)]
mod tests {
    #[test]
    fn probe_requires_art() {
        // On a host without a JVM this must fail cleanly instead of crashing.
        assert!(super::probe().is_err());
    }
}
