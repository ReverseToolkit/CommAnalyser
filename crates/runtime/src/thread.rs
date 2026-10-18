/// Current thread id (the kernel's `tid`, not the pthread handle).
#[inline]
pub fn current_id() -> u32 {
    // SAFETY: SYS_gettid takes no arguments and cannot fail meaningfully.
    unsafe { libc::syscall(libc::SYS_gettid) as u32 }
}

#[cfg(test)]
mod tests {
    #[test]
    fn tid_is_positive() {
        assert!(super::current_id() > 0);
    }
}
