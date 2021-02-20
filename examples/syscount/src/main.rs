use anyhow::Result;
use bpf::{BpfBuilder, U32, U64};
use std::time::Duration;
use zerocopy::{AsBytes, FromBytes, Unaligned};

static PROBE: &[u8] = include_bytes!(concat!(
    env!("OUT_DIR"),
    "/target/bpf/programs/syscount-probe/syscount-probe.elf",
));

#[derive(Clone, Copy, Default, AsBytes, FromBytes, Unaligned)]
#[repr(C)]
pub struct SyscallInfo {
    pub count: U64,
    pub time_ns: U64,
}

fn main() -> Result<()> {
    bpf::utils::sudo::escalate_if_needed().unwrap();
    let mut bpf = BpfBuilder::new(PROBE)?
        .attach_probe_str("tracepoint:raw_syscalls:sys_enter", "sys_enter")?
        .attach_probe_str("tracepoint:raw_syscalls:sys_exit", "sys_exit")?
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
            println!("{:10} {:6} {:10}", name, info.count, info.time_ns);
        }
    }
}
