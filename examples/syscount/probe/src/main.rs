#![no_std]
#![no_main]

use bpf_helpers::{entry, map, program, HashMap, Instant, PidTgid, StackTrace};
use syscount_probe::SyscallInfo;

program!(0xFFFFFFFE, b"GPL");

/*#[entry("kprobe")]
fn kprobe(_: &pt_regs) {}

#[entry("raw_syscalls:sys_enter")]
fn tracepoint(_: &SysEnter) {}

#[entry("perf_event")]
fn perf_event(_: &bpf_perf_event_data) {}*/

const FILTER_PID: Option<u32> = None;
const FILTER_FAILED: bool = true;
const FILTER_ERRNO: Option<i64> = None;
const BY_PROCESS: bool = false;

#[map]
static mut START: HashMap<PidTgid, Instant> = HashMap::with_max_entries(1024);
#[map]
static mut DATA: HashMap<u32, SyscallInfo> = HashMap::with_max_entries(1024);
#[map]
static mut STACK: StackTrace = StackTrace::with_max_entries(1024);

#[entry("raw_syscalls:sys_enter")]
fn sys_enter(_args: &SysEnter) {
    let pid_tgid = PidTgid::current();
    if let Some(pid) = FILTER_PID {
        if pid != pid_tgid.pid() {
            return;
        }
    }
    let time = Instant::now();
    unsafe {
        START.set(&pid_tgid, &time);
    }
}

#[entry("raw_syscalls:sys_exit")]
fn sys_exit(args: &SysExit) {
    let pid_tgid = PidTgid::current();
    if let Some(pid) = FILTER_PID {
        if pid != pid_tgid.pid() {
            return;
        }
    }
    if FILTER_FAILED {
        if args.ret >= 0 {
            return;
        }
    }
    if let Some(errno) = FILTER_ERRNO {
        if args.ret != -errno {
            return;
        }
    }
    let key = if BY_PROCESS {
        pid_tgid.pid()
    } else {
        args.id as u32
    };
    unsafe {
        if let Some(start) = START.get(&pid_tgid) {
            let mut entry = DATA.get(&key).copied().unwrap_or_default();
            entry.count += 1;
            entry.time += start.elapsed();
            DATA.set(&key, &entry);
        }
    }
}

#[entry("perf_event")]
fn profile(ev: &bpf_perf_event_data) {
    panic!("{:?}", ev);
    //STACK.stack_id(ev.sample_period, BPF_F_USER_STACK as _);
}
