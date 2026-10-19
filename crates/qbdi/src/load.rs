//! Statically linked TAL (`tal_prepare` / `tal_enter`). No `dlopen`.

use runtime::Result;

#[repr(C)]
#[derive(Clone, Copy)]
pub struct TalCpuContext {
    pub x: [u64; 29],
    pub fp: u64,
    pub lr: u64,
    pub sp: u64,
    pub nzcv: u64,
    pub pc: u64,
    pub q: [u128; 8],
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
    pub enter: unsafe extern "C" fn(*mut TalCpuContext) -> i32,
    pub take_events: unsafe extern "C" fn(*mut TalEvent, usize) -> usize,
    pub add_escape: unsafe extern "C" fn(u64, u64),
}

extern "C" {
    fn tal_prepare(addr: u64, end: u64, all: i32, mode: i32) -> i32;
    fn tal_enter(cpu: *mut TalCpuContext) -> i32;
    fn tal_take_events(out: *mut TalEvent, cap: usize) -> usize;
    fn add_escape(break_addr: u64, resume_addr: u64);
}

pub fn api() -> Result<&'static Api> {
    static API: Api = Api {
        prepare: tal_prepare,
        enter: tal_enter,
        take_events: tal_take_events,
        add_escape,
    };
    Ok(&API)
}
