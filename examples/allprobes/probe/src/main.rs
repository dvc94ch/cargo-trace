#![no_std]
#![no_main]

use bpf_helpers::{entry, map, program, sys, Array, HashMap, StackTrace};

program!(0xFFFF_FFFE, b"GPL");

#[map]
static PROBE_COUNT: HashMap<u32, u32> = HashMap::with_max_entries(13);
#[map]
static USER_COUNT: HashMap<u32, u32> = HashMap::with_max_entries(1024);
#[map]
static USER_STACKS: StackTrace = StackTrace::with_max_entries(1024);
#[map]
static KERNEL_COUNT: HashMap<u32, u32> = HashMap::with_max_entries(1024);
#[map]
static KERNEL_STACKS: StackTrace = StackTrace::with_max_entries(1024);
#[map]
static USER_STACKS_BUILDID: Array<[sys::bpf_stack_build_id; 127]> = Array::with_max_entries(1);

#[inline(always)]
fn increase_counter(n: u32) {
    let mut count = PROBE_COUNT.get(&n).unwrap_or_default();
    count += 1;
    PROBE_COUNT.insert(&n, &count);
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
fn profile(args: &bpf_perf_event_data) {
    increase_counter(6);
    if let Ok(kid) = KERNEL_STACKS.stack_id(args as *const _ as *const _, StackTrace::KERNEL_STACK)
    {
        let mut count = KERNEL_COUNT.get(&kid).unwrap_or_default();
        count += 1;
        KERNEL_COUNT.insert(&kid, &count);
    }
    if let Ok(uid) = USER_STACKS.stack_id(args as *const _ as *const _, StackTrace::USER_STACK) {
        let mut count = USER_COUNT.get(&uid).unwrap_or_default();
        count += 1;
        USER_COUNT.insert(&uid, &count);

        if count == 0 {
            /*unsafe {
                sys::bpf_get_stack(
                    args as *const _ as *mut _,
                    USER_STACKS_BUILDID.lookup(&0) as *mut _,
                    core::mem::size_of::<[sys::bpf_stack_build_id; 127]>() as _,
                    (sys::BPF_F_USER_STACK | sys::BPF_F_USER_BUILD_ID) as _,
                );
            }*/
        }
    }
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
