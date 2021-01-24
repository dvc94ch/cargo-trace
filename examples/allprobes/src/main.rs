use anyhow::Result;
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
    let mut bpf = BpfBuilder::new(PROBE)?
        .attach_probe("kprobe:finish_task_switch", "kprobe")?
        .attach_probe("kretprobe:finish_task_switch", "kretprobe")?
        //.attach_probe("uprobe:/path:symbol")?
        //.attach_probe("uretprobe:/path:symbol")?
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
    let map = bpf.hash_map::<U32, U32>("PROBE_COUNT")?;
    std::thread::sleep(Duration::from_millis(1000));
    for (probe, count) in map.iter() {
        println!("{} {}", PROBES[probe.get() as usize], count.get());
    }
    Ok(())
}
