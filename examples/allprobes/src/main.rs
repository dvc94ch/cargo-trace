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
    bpf::utils::sudo::escalate_if_needed().unwrap();
    let mut builder = BpfBuilder::new(PROBE)?;
    builder.attach_probe_str("kprobe:finish_task_switch", "kprobe")?;
    builder.attach_probe_str("kretprobe:finish_task_switch", "kretprobe")?;
    builder.attach_probe_str("uprobe:/usr/lib/libc-2.33.so:malloc", "uprobe")?;
    builder.attach_probe_str("uretprobe:/usr/lib/libc-2.33.so:free", "uretprobe")?;
    //builder.attach_probe_str("usdt:/path:probe")?;
    builder.attach_probe_str("tracepoint:raw_syscalls:sys_enter", "tracepoint")?;
    builder.attach_probe_str("profile:hz:99", "profile")?;
    builder.attach_probe_str("interval:ms:100", "interval")?;
    builder.attach_probe_str("software:cs:1", "software")?;
    builder.attach_probe_str("hardware:cache-misses:1", "hardware")?;
    //builder.attach_probe_str("watchpoint:address:length:mode", "watchpoint")?;
    //builder.attach_probe_str("kfunc:func", "kfunc")?;
    //builder.attach_probe_str("kretfunc:func", "kretfunc")?;
    let mut bpf = builder.load()?;

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
