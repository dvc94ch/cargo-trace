#![no_std]
use core::time::Duration;

#[derive(Clone, Copy, Default)]
#[repr(C)]
pub struct SyscallInfo {
    pub count: u64,
    pub time: Duration,
}
