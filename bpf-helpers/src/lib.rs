#![no_std]
#[allow(clippy::missing_safety_doc)]

mod map;
mod pid;
mod time;

pub use crate::map::*;
pub use crate::pid::*;
pub use crate::time::*;
pub use bpf_helpers_sys as sys;
pub use bpf_macros::*;
pub use cty;

pub type I16 = zerocopy::byteorder::I16<byteorder::NativeEndian>;
pub type I32 = zerocopy::byteorder::I32<byteorder::NativeEndian>;
pub type I64 = zerocopy::byteorder::I64<byteorder::NativeEndian>;
pub type U16 = zerocopy::byteorder::U16<byteorder::NativeEndian>;
pub type U32 = zerocopy::byteorder::U32<byteorder::NativeEndian>;
pub type U64 = zerocopy::byteorder::U64<byteorder::NativeEndian>;

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
