use anyhow::Result;
use bpf::utils::{escalate_if_needed, BinaryInfo};
use bpf::{BpfBuilder, U32};
use cargo_subcommand::Subcommand;

static PROBE: &[u8] = include_bytes!(concat!(
    env!("OUT_DIR"),
    "/target/bpf/programs/cargo-trace-probe/cargo-trace-probe.elf",
));

fn main() -> Result<()> {
    escalate_if_needed().unwrap();
    let args = "cargo flamegraph -- --example hello_world"
        .split(' ')
        .map(|s| s.to_string());
    let cmd = Subcommand::new(args, "flamegraph", |_, _| Ok(false))?;
    let info = BinaryInfo::from_cargo_subcommand(&cmd)?;
    info.precompile_ehframes(".".as_ref())?;
    println!("{}", info.to_string());
    let pid = info.spawn()?;
    // TODO: load memory map

    let mut bpf = BpfBuilder::new(PROBE)?
        .set_child_pid(pid)
        .attach_probe("profile:hz:99", "profile")?
        .load()?;

    // TODO: load address/instruction data into hashmaps

    pid.cont_and_wait()?;

    /*let user_count = bpf
        .hash_map::<U32, U32>("USER_COUNT")?
        .iter()
        .collect::<Vec<_>>();
    let user_stacks = bpf.stack_trace("USER_STACKS")?;
    for (stackid, count) in user_count {
        let ustack = user_stacks.raw_stack_trace(stackid.get())?.unwrap();
        println!("ustack observed {} times:", count);
        for (i, ip) in ustack.iter().enumerate() {
            println!("  {}: 0x{:x}", i, ip);
        }
    }*/

    Ok(())
}
