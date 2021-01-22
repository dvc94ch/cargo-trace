use anyhow::Result;
use bpf::{BpfBuilder, U32};
use std::time::Duration;
use syscount_probe::SyscallInfo;

static PROBE: &[u8] = include_bytes!(concat!(
    env!("OUT_DIR"),
    "/target/bpf/programs/syscount_probe/syscount_probe.elf",
));

fn main() -> Result<()> {
    let mut bpf = BpfBuilder::new(PROBE)?
        .attach_probe("tracepoint:raw_syscalls:sys_enter", "sys_enter")?
        .attach_probe("tracepoint:raw_syscalls:sys_exit", "sys_exit")?
        .load()?;
    let data = bpf.hash_map::<U32, SyscallInfo>("DATA")?;
    let table = bpf::utils::syscall_table()?;
    println!("{:10} {:6} {:10}", "SYSCALL", "COUNT", "NS");
    loop {
        std::thread::sleep(Duration::from_millis(250));

        for (syscall, info) in data.iter() {
            let name = table
                .get(&syscall.get())
                .cloned()
                .unwrap_or_else(|| syscall.to_string());
            println!("{:10} {:6} {:10}", name, info.count, info.time.as_nanos());
        }
    }
}
