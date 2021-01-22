#![no_std]
use bpf_helpers::{Duration, U64};
use zerocopy::{AsBytes, FromBytes, Unaligned};

#[derive(Clone, Copy, Default, AsBytes, FromBytes, Unaligned)]
#[repr(C)]
pub struct SyscallInfo {
    pub count: U64,
    pub time: Duration,
}
