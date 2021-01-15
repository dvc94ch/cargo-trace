use anyhow::Result;
use bpf::BpfBuilder;
//use std::time::Duration;
//use syscount_probe::SyscallInfo;

static PROBE: &[u8] = include_bytes!(concat!(
    env!("OUT_DIR"),
    "/target/bpf/programs/syscount_probe/syscount_probe.elf",
));

fn main() -> Result<()> {
    let bpf = BpfBuilder::new(PROBE)?
        .attach_probe("tracepoint:raw_syscalls:sys_enter", "sys_enter")?
        .attach_probe("tracepoint:raw_syscalls:sys_exit", "sys_exit")?
        .attach_probe("profile:hz:99", "profile")?
        .load()?;

    // let data = obj.map("data")?.unwrap();
    // BpfHashMap::<u32, SyscallInfo>::attach(data)?;

    /*
    let table = bpf_utils::syscall::syscall_table()?;
    let data = HashMap::<u32, SyscallInfo>::new(loader.map("data").unwrap()).unwrap();

    println!("{:10} {:6} {:10}", "SYSCALL", "COUNT", "NS");

    loop {
        std::thread::sleep(Duration::from_millis(250));

        for (syscall, info) in data.iter() {
            let name = table
                .get(&syscall)
                .cloned()
                .unwrap_or_else(|| syscall.to_string());
            println!("{:10} {:6} {:10}", name, info.count, info.total_ns);
        }
    }
    */
    Ok(())
}
