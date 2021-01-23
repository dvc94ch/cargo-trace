#![no_std]
#![no_main]

use bpf_helpers::{entry, map, program, HashMap, U32};

program!(0xFFFF_FFFE, b"GPL");

#[map]
static PROBE_COUNT: HashMap<U32, U32> = HashMap::with_max_entries(10);

#[entry("kprobe")]
fn kprobe(_args: &pt_regs) {
    PROBE_COUNT.get_or_default(&U32::new(0), |count| {
        count.set(count.get() + 1);
    });
}

#[entry("kprobe")]
fn kretprobe(_args: &pt_regs) {
    PROBE_COUNT.get_or_default(&U32::new(1), |count| {
        count.set(count.get() + 1);
    });
}

#[entry("raw_syscalls:sys_enter")]
fn tracepoint(_args: &SysEnter) {
    PROBE_COUNT.get_or_default(&U32::new(2), |count| {
        count.set(count.get() + 1);
    });
}
