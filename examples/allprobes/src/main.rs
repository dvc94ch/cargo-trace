use anyhow::Result;
use bpf::utils::KernelSymbolTable;
use bpf::{BpfBuilder, U32};
use std::time::Duration;

static PROBE: &[u8] = include_bytes!(concat!(
    env!("OUT_DIR"),
    "/target/bpf/programs/allprobes-probe/allprobes-probe.elf",
));

static PROBES: &[&str] = &[
    "kprobe",
    "kretprobe",
    "uprobe",
    "uretprobe",
    "usdt",
    "tracepoint",
    "profile",
    "interval",
    "software",
    "hardware",
    "watchpoint",
    "kfunc",
    "kretfunc",
];

fn main() -> Result<()> {
    bpf::utils::escalate_if_needed().unwrap();
    let mut bpf = BpfBuilder::new(PROBE)?
        .attach_probe("kprobe:finish_task_switch", "kprobe")?
        .attach_probe("kretprobe:finish_task_switch", "kretprobe")?
        .attach_probe("uprobe:/usr/lib/libc-2.32.so:malloc", "uprobe")?
        .attach_probe("uretprobe:/usr/lib/libc-2.32.so:free", "uretprobe")?
        //.attach_probe("usdt:/path:probe")?
        .attach_probe("tracepoint:raw_syscalls:sys_enter", "tracepoint")?
        .attach_probe("profile:hz:99", "profile")?
        .attach_probe("interval:ms:100", "interval")?
        .attach_probe("software:cs:1", "software")?
        .attach_probe("hardware:cache-misses:1", "hardware")?
        //.attach_probe("watchpoint:address:length:mode", "watchpoint")?
        //.attach_probe("kfunc:func", "kfunc")?
        //.attach_probe("kretfunc:func", "kretfunc")?
        .load()?;

    std::thread::sleep(Duration::from_millis(1000));

    let map = bpf.hash_map::<U32, U32>("PROBE_COUNT")?;
    for (probe, count) in map.iter() {
        println!("{} {}", PROBES[probe.get() as usize], count.get());
    }

    let map = bpf.hash_map::<U32, U32>("USER_COUNT")?;
    let mut uid = None;
    for (stackid, count) in map.iter() {
        if uid.is_none() {
            uid = Some(stackid);
        }
        if count.get() > 1 {
            println!("user {} {}", stackid.get(), count.get());
        }
    }
    let map = bpf.stack_trace("USER_STACKS")?;
    let ustack = map.raw_stack_trace(uid.unwrap().get())?.unwrap();
    println!("ustack:");
    for (i, ip) in ustack.iter().enumerate() {
        println!("  {}: 0x{:x}", i, ip);
    }

    let map = bpf.hash_map::<U32, U32>("KERNEL_COUNT")?;
    let mut kid = None;
    for (stackid, count) in map.iter() {
        if kid.is_none() {
            kid = Some(stackid);
        }
        if count.get() > 1 {
            println!("kernel {} {}", stackid.get(), count.get());
        }
    }
    let map = bpf.stack_trace("KERNEL_STACKS")?;
    let kstack = map.raw_stack_trace(kid.unwrap().get())?.unwrap();
    let ksyms = KernelSymbolTable::load()?;
    println!("kstack:");
    for (i, ip) in kstack.iter().enumerate() {
        let (sym, offset) = ksyms.symbol(ip as _);
        println!("  {}: {}+{}", i, sym, offset);
        println!("        at 0x{:x}", ip);
    }
    Ok(())
}
