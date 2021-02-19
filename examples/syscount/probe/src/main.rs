#![no_std]
#![no_main]

use bpf_helpers::{entry, map, program, HashMap, Instant, PidTgid};

program!(0xFFFF_FFFE, b"GPL");

const FILTER_PID: Option<u32> = None;
const FILTER_FAILED: bool = true;
const FILTER_ERRNO: Option<i64> = None;
const BY_PROCESS: bool = false;

#[map]
static START: HashMap<PidTgid, Instant> = HashMap::with_max_entries(1024);
#[map]
static DATA: HashMap<u32, SyscallInfo> = HashMap::with_max_entries(1024);

#[derive(Clone, Copy, Default)]
#[repr(C)]
pub struct SyscallInfo {
    pub count: u64,
    pub time_ns: u64,
}

#[entry("raw_syscalls:sys_enter")]
fn sys_enter(_args: &SysEnter) {
    let pid_tgid = PidTgid::current();
    if let Some(pid) = FILTER_PID {
        if pid != pid_tgid.pid() {
            return;
        }
    }
    let time = Instant::now();
    START.insert(&pid_tgid, &time);
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
    if let Some(start) = START.get(&pid_tgid) {
        let mut entry = DATA.get(&key).unwrap_or_default();
        entry.count += 1;
        entry.time_ns += start.elapsed().as_nanos();
        DATA.insert(&key, &entry);
    }
}
