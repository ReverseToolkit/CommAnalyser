//! Integer/pointer calls into `il2cpp_*` and method bodies.
//!
//! IL2CPP's exported API is pointer-and-integer. Float returns are read from
//! `d0` only when a method body needs them.

use runtime::{Error, Result};

/// Call `target` with up to eight integer arguments and return `x0`.
///
/// # Safety
/// `target` must be a C function, and `args` must match its ABI.
pub unsafe fn call(target: usize, args: &[u64]) -> Result<u64> {
    if target == 0 {
        return Err(Error::Parse("il2cpp call: null target".into()));
    }
    if args.len() > 8 {
        return Err(Error::Unsupported("il2cpp call: more than 8 arguments"));
    }
    let mut x = [0u64; 8];
    x[..args.len()].copy_from_slice(args);
    #[cfg(target_arch = "aarch64")]
    {
        let mut ret: u64;
        // SAFETY: caller supplied a C function. `blr` is a valid BTI caller.
        unsafe {
            core::arch::asm!(
                "blr {f}",
                f = in(reg) target,
                inout("x0") x[0] => ret,
                in("x1") x[1],
                in("x2") x[2],
                in("x3") x[3],
                in("x4") x[4],
                in("x5") x[5],
                in("x6") x[6],
                in("x7") x[7],
                clobber_abi("C"),
            );
        }
        Ok(ret)
    }
    #[cfg(not(target_arch = "aarch64"))]
    {
        let function = unsafe {
            std::mem::transmute::<
                usize,
                unsafe extern "C" fn(u64, u64, u64, u64, u64, u64, u64, u64) -> u64,
            >(target)
        };
        Ok(unsafe { function(x[0], x[1], x[2], x[3], x[4], x[5], x[6], x[7]) })
    }
}

pub fn call_ptr(target: usize, args: &[u64]) -> Result<u64> {
    unsafe { call(target, args) }
}
