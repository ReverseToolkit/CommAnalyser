/// One `/proc/self/task` entry, as Frida's `Process.enumerateThreads`.
#[derive(Clone, Debug)]
pub struct ThreadInfo {
    pub id: u32,
    pub name: String,
    pub state: String,
}

/// Current thread id (the kernel's `tid`, not the pthread handle).
#[inline]
pub fn current_id() -> u32 {
    // SAFETY: SYS_gettid takes no arguments and cannot fail meaningfully.
    unsafe { libc::syscall(libc::SYS_gettid) as u32 }
}

/// Enumerate threads of this process from `/proc/self/task`.
pub fn enumerate() -> crate::Result<Vec<ThreadInfo>> {
    let mut threads = Vec::new();
    let dir = std::fs::read_dir("/proc/self/task").map_err(crate::Error::Io)?;
    for entry in dir.flatten() {
        let id = entry
            .file_name()
            .to_string_lossy()
            .parse::<u32>()
            .unwrap_or(0);
        if id == 0 {
            continue;
        }
        let comm = std::fs::read_to_string(format!("/proc/self/task/{id}/comm"))
            .unwrap_or_default()
            .trim()
            .to_owned();
        let state = std::fs::read_to_string(format!("/proc/self/task/{id}/stat"))
            .ok()
            .and_then(|text| {
                let close = text.rfind(')')?;
                text[close + 1..]
                    .split_whitespace()
                    .next()
                    .map(str::to_owned)
            })
            .unwrap_or_else(|| "?".into());
        threads.push(ThreadInfo {
            id,
            name: comm,
            state,
        });
    }
    Ok(threads)
}

/// Return addresses of the current stack (`Thread.backtrace`).
pub fn backtrace(limit: usize) -> Vec<usize> {
    let cap = limit.clamp(1, 64);
    #[cfg(all(unix, target_env = "gnu"))]
    {
        let mut buf = vec![std::ptr::null_mut::<libc::c_void>(); cap];
        // SAFETY: buffer is writable for `cap` slots.
        let n = unsafe { libc::backtrace(buf.as_mut_ptr(), cap as i32) };
        if n > 0 {
            buf.truncate(n as usize);
            return buf
                .into_iter()
                .map(|pointer| pointer as usize)
                .filter(|pointer| *pointer != 0)
                .collect();
        }
    }
    let _ = cap;
    Vec::new()
}

#[cfg(test)]
mod tests {
    #[test]
    fn tid_is_positive() {
        assert!(super::current_id() > 0);
        let threads = super::enumerate().unwrap();
        assert!(threads
            .iter()
            .any(|thread| thread.id == super::current_id()));
    }
}
