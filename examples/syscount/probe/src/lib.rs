#![no_std]
use bpf_helpers::Duration;

#[derive(Clone, Copy, Default)]
pub struct SyscallInfo {
    pub count: u64,
    pub time: Duration,
}
