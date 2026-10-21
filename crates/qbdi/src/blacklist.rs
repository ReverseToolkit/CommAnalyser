//! TAL-style default exclusions: do not instrument libc/ART/linker/agent.

/// Substrings matched against `/proc/self/maps` path or basename.
/// Android `removeConflictModule` names. Only executable maps are removed.
pub const ANDROID_CONFLICT: &[&str] = &[
    "libart.so",
    "libEGL.so",
    "linker",
    "libart-compiler.so",
    "libnativehelper.so",
    "libandroid_runtime.so",
    "libandroidfw.so",
    "libandroid.so",
    "libbinder.so",
    "libc++.so",
    "libc++_shared.so",
    "libc.so",
    "liblog.so",
    "libGLESv1_CM.so",
    ".oat",
];

/// Whether `name` (path or basename) is in the default conflict set.
pub fn is_conflict(name: &str) -> bool {
    ANDROID_CONFLICT.iter().any(|needle| name.contains(needle))
}

/// Whether `name` is excluded by the default set or `extra` needles.
pub fn is_excluded(name: &str, extra: &[String]) -> bool {
    is_conflict(name) || extra.iter().any(|needle| name.contains(needle.as_str()))
}

/// Executable mappings that should be removed from the instrumented set.
pub fn excluded_executable_ranges(extra: &[String]) -> runtime::Result<Vec<(u64, u64)>> {
    let maps = runtime::maps::read_self_maps()?;
    Ok(maps
        .into_iter()
        .filter(|mapping| mapping.perms.exec)
        .filter(|mapping| {
            let path = mapping.clean_path().unwrap_or("");
            is_excluded(path, extra)
        })
        .map(|mapping| (mapping.range.start as u64, mapping.range.end as u64))
        .collect())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn matches_tal_android_names() {
        assert!(is_conflict("libc.so"));
        assert!(is_conflict(
            "/apex/com.android.runtime/lib64/bionic/libc.so"
        ));
        assert!(is_conflict("libart.so"));
        assert!(is_conflict("/system/bin/linker64"));
        assert!(is_conflict("boot.oat"));
        assert!(!is_conflict("/data/local/tmp/libagent.so"));
        assert!(!is_conflict("libQBDI.so"));
        assert!(!is_conflict("libfoo.so"));
        assert!(!is_conflict("/system/lib64/libm.so"));
        assert!(is_excluded(
            "/data/app/libextra.so",
            &["libextra.so".into()]
        ));
        assert!(!is_excluded(
            "/system/lib64/libm.so",
            &["libextra.so".into()]
        ));
    }
}
