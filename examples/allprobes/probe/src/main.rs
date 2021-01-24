#![no_std]
#![no_main]

use bpf_helpers::{entry, map, program, HashMap, U32};

program!(0xFFFF_FFFE, b"GPL");

#[map]
static PROBE_COUNT: HashMap<U32, U32> = HashMap::with_max_entries(13);

#[inline(always)]
fn increase_counter(n: u32) {
    PROBE_COUNT.get_or_default(&U32::new(n), |count| {
        count.set(count.get() + 1);
    });
}

#[entry("kprobe")]
fn kprobe(_args: &pt_regs) {
    increase_counter(0)
}

#[entry("kprobe")]
fn kretprobe(_args: &pt_regs) {
    increase_counter(1)
}

#[entry("kprobe")]
fn uprobe(_args: &pt_regs) {
    increase_counter(2)
}

#[entry("kprobe")]
fn uretprobe(_args: &pt_regs) {
    increase_counter(3)
}

#[entry("kprobe")]
fn usdt(_args: &pt_regs) {
    increase_counter(4)
}

#[entry("raw_syscalls:sys_enter")]
fn tracepoint(_args: &SysEnter) {
    increase_counter(5)
}

#[entry("perf_event")]
fn profile(_args: &bpf_perf_event_data) {
    increase_counter(6)
}

#[entry("perf_event")]
fn interval(_args: &bpf_perf_event_data) {
    increase_counter(7)
}

#[entry("perf_event")]
fn software(_args: &bpf_perf_event_data) {
    increase_counter(8)
}

#[entry("perf_event")]
fn hardware(_args: &bpf_perf_event_data) {
    increase_counter(9)
}

#[entry("perf_event")]
fn watchpoint(_args: &bpf_perf_event_data) {
    increase_counter(10)
}

/*#[entry("tracing")]
fn kfunc(_args: &core::ffi::c_void) {
    increase_counter(11)
}*/

/*#[entry("tracing")]
fn kretfunc(_args: &core::ffi::c_void) {
    increase_counter(12)
}*/
