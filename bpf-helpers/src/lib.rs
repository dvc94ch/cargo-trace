#![no_std]

mod map;
mod pid;
mod time;

pub use crate::map::*;
pub use crate::pid::*;
pub use crate::time::*;
pub use bpf_macros::*;
pub use cty;

#[inline]
pub fn bpf_trace_printk(msg: &[u8]) -> usize {
    unsafe {
        let f: unsafe extern "C" fn(fmt: *const cty::c_char, fmt_size: u32) -> cty::c_int =
            core::mem::transmute(6usize);
        f(msg.as_ptr() as *const _ as *const _, msg.len() as _) as _
    }
}

pub mod kprobe {
    pub use bpf_helpers_sys::pt_regs;
}

pub mod tracepoint {}

pub mod perf_event {
    pub use bpf_helpers_sys::bpf_perf_event_data;
}

pub mod raw_tracepoint {}

pub mod raw_tracepoint_writable {}

pub mod tracing {}
