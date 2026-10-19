//! Decompress the embedded `libtal.so` and `dlopen` it on first Trace.

use std::ffi::{c_char, c_void, CStr, CString};
use std::io::Read;
use std::path::PathBuf;
use std::ptr;
use std::sync::{Mutex, OnceLock};

use flate2::read::GzDecoder;
use runtime::{Error, Result};

const BLOB: &[u8] = include_bytes!(concat!(env!("OUT_DIR"), "/libtal.so.gz"));
const CXX_BLOB: &[u8] = include_bytes!(concat!(env!("OUT_DIR"), "/libc++_shared.so.gz"));

const RTLD_NOW: i32 = 2;
const RTLD_GLOBAL: i32 = 0x100;
const ANDROID_DLEXT_USE_LIBRARY_FD: u64 = 0x10;

#[repr(C)]
struct AndroidDlExt {
    flags: u64,
    reserved_addr: *mut c_void,
    reserved_size: usize,
    relro_fd: i32,
    library_fd: i32,
    library_fd_offset: i64,
    library_namespace: *mut c_void,
}

#[repr(C)]
#[derive(Clone, Copy)]
pub struct TalCpuContext {
    pub x: [u64; 29],
    pub fp: u64,
    pub lr: u64,
    pub sp: u64,
    pub nzcv: u64,
    pub pc: u64,
}

#[repr(C)]
#[derive(Clone, Copy, Default)]
pub struct TalEvent {
    pub kind: u32,
    pub size: u32,
    pub pc: u64,
    pub mem_addr: u64,
    pub mem_value: u64,
    pub is_write: u32,
}

#[derive(Clone, Copy)]
pub struct Api {
    pub prepare: unsafe extern "C" fn(u64, u64, i32, i32) -> i32,
    pub enter: unsafe extern "C" fn(*const TalCpuContext) -> i32,
    pub take_events: unsafe extern "C" fn(*mut TalEvent, usize) -> usize,
    pub add_escape: unsafe extern "C" fn(u64, u64),
}

struct Loaded {
    _cxx: Option<inject::loader::MappedLibrary>,
    _mapped: Option<inject::loader::MappedLibrary>,
    _handle: *mut c_void,
    api: Api,
}

unsafe impl Send for Loaded {}
unsafe impl Sync for Loaded {}

static LOCK: Mutex<()> = Mutex::new(());
static LOADED: OnceLock<Loaded> = OnceLock::new();

pub fn api() -> Result<&'static Api> {
    Ok(&ensure()?.api)
}

fn ensure() -> Result<&'static Loaded> {
    if let Some(loaded) = LOADED.get() {
        return Ok(loaded);
    }
    let _guard = LOCK.lock().unwrap_or_else(|err| err.into_inner());
    if let Some(loaded) = LOADED.get() {
        return Ok(loaded);
    }
    let loaded = load_now()?;
    Ok(LOADED.get_or_init(|| loaded))
}

fn load_now() -> Result<Loaded> {
    if BLOB.is_empty() {
        return Err(Error::Unsupported(
            "TAL payload was not embedded (libtal.so missing at build)",
        ));
    }
    let mut decoder = GzDecoder::new(BLOB);
    let mut so = Vec::new();
    decoder
        .read_to_end(&mut so)
        .map_err(|err| Error::Parse(format!("TAL decompress: {err}")))?;
    if so.len() < 64 || &so[..4] != b"\x7fELF" {
        return Err(Error::Parse(
            "TAL payload is not an ELF shared object".into(),
        ));
    }
    let (handle, cxx, mapped, api) = unsafe { open_library(&so)? };
    Ok(Loaded {
        _cxx: cxx,
        _mapped: mapped,
        _handle: handle,
        api,
    })
}

unsafe fn open_library(
    bytes: &[u8],
) -> Result<(
    *mut c_void,
    Option<inject::loader::MappedLibrary>,
    Option<inject::loader::MappedLibrary>,
    Api,
)> {
    let path = cache_path()?;
    if let Some(parent) = path.parent() {
        let _ = std::fs::create_dir_all(parent);
        // Prefer an already-relabeled file (root `chcon system_lib_file`).
        // Rewriting would restore `system_app_data_file` and lose execute.
        let cxx = parent.join("libc++_shared.so");
        if cxx.is_file() {
            let _ = dlopen_path(&cxx, RTLD_NOW | RTLD_GLOBAL);
        }
        if path.is_file() {
            if let Ok(handle) = dlopen_path(&path, RTLD_NOW) {
                let api = resolve(handle)?;
                return Ok((handle, None, None, api));
            }
        }
        let _ = preload_cxx(parent);
        if let Ok(handle) = file_dlopen_at(&path, bytes) {
            let api = resolve(handle)?;
            return Ok((handle, None, None, api));
        }
    }
    #[cfg(target_os = "android")]
    {
        if let Ok(handle) = memfd_dlopen(bytes) {
            let api = resolve(handle)?;
            return Ok((handle, None, None, api));
        }
    }
    match map_anonymous_so(bytes) {
        Ok((handle, cxx, mapped, api)) => Ok((handle, cxx, Some(mapped), api)),
        Err(map_err) => Err(Error::Parse(format!("TAL map: {map_err}"))),
    }
}

fn decompress_cxx() -> Result<Vec<u8>> {
    if CXX_BLOB.is_empty() {
        return Ok(Vec::new());
    }
    let mut decoder = GzDecoder::new(CXX_BLOB);
    let mut so = Vec::new();
    decoder
        .read_to_end(&mut so)
        .map_err(|err| Error::Parse(format!("c++_shared decompress: {err}")))?;
    Ok(so)
}

fn map_anonymous_so(
    bytes: &[u8],
) -> Result<(
    *mut c_void,
    Option<inject::loader::MappedLibrary>,
    inject::loader::MappedLibrary,
    Api,
)> {
    let cxx_bytes = decompress_cxx()?;
    let cxx = if cxx_bytes.is_empty() {
        None
    } else {
        Some(
            inject::loader::MappedLibrary::load_no_init(&cxx_bytes, inject::loader::dlsym_default)
                .map_err(|err| Error::Parse(format!("map libc++_shared: {err}")))?,
        )
    };
    let resolve = |name: &str| {
        if let Some(cxx) = cxx.as_ref() {
            if let Some(addr) = cxx.symbol(name) {
                return Ok(addr as u64);
            }
        }
        inject::loader::dlsym_default(name)
    };
    let mapped = inject::loader::MappedLibrary::load_no_init(bytes, resolve)
        .map_err(|err| Error::Parse(format!("anonymous map: {err}")))?;
    let api = resolve_mapped(&mapped)?;
    let handle = mapped.base() as *mut c_void;
    Ok((handle, cxx, mapped, api))
}

fn resolve_mapped(mapped: &inject::loader::MappedLibrary) -> Result<Api> {
    Ok(Api {
        prepare: mapped_sym(mapped, "tal_prepare")?,
        enter: mapped_sym(mapped, "tal_enter")?,
        take_events: mapped_sym(mapped, "tal_take_events")?,
        add_escape: mapped_sym(mapped, "add_escape")?,
    })
}

fn mapped_sym<T>(mapped: &inject::loader::MappedLibrary, name: &str) -> Result<T> {
    let ptr = mapped
        .symbol(name)
        .ok_or_else(|| Error::Parse(format!("TAL missing {name}")))?;
    // SAFETY: `T` matches the C_EXPORT in TAL library.h.
    Ok(unsafe { std::mem::transmute_copy(&ptr) })
}

#[cfg(target_os = "android")]
unsafe fn memfd_dlopen(bytes: &[u8]) -> Result<*mut c_void> {
    let name = CString::new("libtal.so").expect("no NUL in soname");
    // Android 15 memfd is noexec unless MFD_EXEC (0x10) is set.
    let fd = libc::memfd_create(name.as_ptr(), libc::MFD_CLOEXEC | 0x10);
    let fd = if fd < 0 {
        libc::memfd_create(name.as_ptr(), libc::MFD_CLOEXEC)
    } else {
        fd
    };
    if fd < 0 {
        return Err(Error::Io(std::io::Error::last_os_error()));
    }
    let mut written = 0usize;
    while written < bytes.len() {
        let n = libc::write(
            fd,
            bytes.as_ptr().add(written).cast(),
            bytes.len() - written,
        );
        if n <= 0 {
            libc::close(fd);
            return Err(Error::Io(std::io::Error::last_os_error()));
        }
        written += n as usize;
    }
    let ext = AndroidDlExt {
        flags: ANDROID_DLEXT_USE_LIBRARY_FD,
        reserved_addr: ptr::null_mut(),
        reserved_size: 0,
        relro_fd: -1,
        library_fd: fd,
        library_fd_offset: 0,
        library_namespace: ptr::null_mut(),
    };
    #[link(name = "dl")]
    extern "C" {
        fn android_dlopen_ext(
            filename: *const c_char,
            flags: i32,
            extinfo: *const AndroidDlExt,
        ) -> *mut c_void;
    }
    let handle = android_dlopen_ext(name.as_ptr(), RTLD_NOW, &ext);
    libc::close(fd);
    if handle.is_null() {
        return Err(Error::Parse(dlerror_text()));
    }
    Ok(handle)
}

unsafe fn file_dlopen_at(path: &std::path::Path, bytes: &[u8]) -> Result<*mut c_void> {
    write_exec_file(path, bytes)?;
    dlopen_path(path, RTLD_NOW)
}

fn write_exec_file(path: &std::path::Path, bytes: &[u8]) -> Result<()> {
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let _ = std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o644));
    }
    std::fs::write(path, bytes).map_err(Error::Io)?;
    // W^X: a just-written file cannot be mapped PROT_EXEC until it is not writable.
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o555))
            .map_err(Error::Io)?;
    }
    Ok(())
}

unsafe fn dlopen_path(path: &std::path::Path, flags: i32) -> Result<*mut c_void> {
    let c_path = CString::new(path.to_string_lossy().as_bytes())
        .map_err(|_| Error::Parse("TAL cache path contains NUL".into()))?;
    #[link(name = "dl")]
    extern "C" {
        fn dlopen(filename: *const c_char, flags: i32) -> *mut c_void;
    }
    let handle = dlopen(c_path.as_ptr(), flags);
    if handle.is_null() {
        return Err(Error::Parse(dlerror_text()));
    }
    Ok(handle)
}

unsafe fn preload_cxx(dir: &std::path::Path) -> Result<()> {
    extract_cxx(dir)?;
    let cxx = dir.join("libc++_shared.so");
    if cxx.is_file() {
        let _ = dlopen_path(&cxx, RTLD_NOW | RTLD_GLOBAL);
    }
    Ok(())
}

fn cache_path() -> Result<PathBuf> {
    let mut dir = std::env::temp_dir();
    if cfg!(target_os = "android") {
        let mut candidates = Vec::new();
        if let Some(pkg) = android_package() {
            // Settings on this device writes under /data/user_de/0 (not /data/user/0).
            for root in ["/data/user_de/0", "/data/user/0", "/data/data"] {
                candidates.push(format!("{root}/{pkg}/code_cache"));
                candidates.push(format!("{root}/{pkg}/cache"));
            }
        }
        candidates.push(std::env::temp_dir().to_string_lossy().into_owned());
        candidates.push("/data/local/tmp".into());
        for candidate in candidates {
            let path = PathBuf::from(&candidate);
            if path.is_dir() || std::fs::create_dir_all(&path).is_ok() {
                let probe = path.join(".ca-tal-write");
                if std::fs::write(&probe, b"1").is_ok() {
                    let _ = std::fs::remove_file(&probe);
                    dir = path;
                    break;
                }
            }
        }
    }
    Ok(dir.join("commanalyser-libtal.so"))
}

fn android_package() -> Option<String> {
    let bytes = std::fs::read("/proc/self/cmdline").ok()?;
    let name = bytes.split(|b| *b == 0).next()?;
    let name = std::str::from_utf8(name).ok()?.to_owned();
    if name.contains('.') {
        Some(name)
    } else {
        None
    }
}

fn extract_cxx(dir: &std::path::Path) -> Result<()> {
    if CXX_BLOB.is_empty() {
        return Ok(());
    }
    let dest = dir.join("libc++_shared.so");
    if dest.is_file() && dest.metadata().map(|m| m.len() > 0).unwrap_or(false) {
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let _ = std::fs::set_permissions(&dest, std::fs::Permissions::from_mode(0o555));
        }
        return Ok(());
    }
    let mut decoder = GzDecoder::new(CXX_BLOB);
    let mut so = Vec::new();
    decoder
        .read_to_end(&mut so)
        .map_err(|err| Error::Parse(format!("c++_shared decompress: {err}")))?;
    write_exec_file(&dest, &so)?;
    Ok(())
}

unsafe fn resolve(handle: *mut c_void) -> Result<Api> {
    Ok(Api {
        prepare: sym(handle, "tal_prepare")?,
        enter: sym(handle, "tal_enter")?,
        take_events: sym(handle, "tal_take_events")?,
        add_escape: sym(handle, "add_escape")?,
    })
}

unsafe fn sym<T>(handle: *mut c_void, name: &str) -> Result<T> {
    #[link(name = "dl")]
    extern "C" {
        fn dlsym(handle: *mut c_void, symbol: *const c_char) -> *mut c_void;
    }
    let c_name = CString::new(name).expect("TAL symbol names are literals");
    let ptr = dlsym(handle, c_name.as_ptr());
    if ptr.is_null() {
        return Err(Error::Parse(format!("TAL missing {name}")));
    }
    // SAFETY: `T` matches the C_EXPORT in TAL library.h.
    Ok(unsafe { std::mem::transmute_copy(&ptr) })
}

fn dlerror_text() -> String {
    extern "C" {
        fn dlerror() -> *mut c_char;
    }
    unsafe {
        let err = dlerror();
        if err.is_null() {
            "dlopen libtal.so failed".into()
        } else {
            CStr::from_ptr(err).to_string_lossy().into_owned()
        }
    }
}
