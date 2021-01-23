use anyhow::Result;
use bpf::{BpfBuilder, U32};
use std::time::Duration;

static PROBE: &[u8] = include_bytes!(concat!(
    env!("OUT_DIR"),
    "/target/bpf/programs/allprobes-probe/allprobes-probe.elf",
));

static PROBES: &[&str] = &["kprobe", "kretprobe", "tracepoint"];

fn main() -> Result<()> {
    let mut bpf = BpfBuilder::new(PROBE)?
        .attach_probe("kprobe:finish_task_switch", "kprobe")?
        .attach_probe("kretprobe:finish_task_switch", "kretprobe")?
        .attach_probe("tracepoint:raw_syscalls:sys_enter", "tracepoint")?
        .load()?;
    let map = bpf.hash_map::<U32, U32>("PROBE_COUNT")?;
    std::thread::sleep(Duration::from_millis(1000));
    for (probe, count) in map.iter() {
        println!("{} {}", PROBES[probe.get() as usize], count.get());
    }
    Ok(())
}
