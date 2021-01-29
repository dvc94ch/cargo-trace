use anyhow::Result;
use bpf::utils::{escalate_if_needed, BinaryInfo};
use bpf::BpfBuilder;
use cargo_subcommand::Subcommand;

static PROBE: &[u8] = include_bytes!(concat!(
    env!("OUT_DIR"),
    "/target/bpf/programs/rust-analysis-probe/rust-analysis-probe.elf",
));

fn main() -> Result<()> {
    escalate_if_needed().unwrap();
    let args = "cargo flamegraph -- --example hello_world"
        .split(' ')
        .map(|s| s.to_string());
    let cmd = Subcommand::new(args, "flamegraph", |_, _| Ok(false))?;
    let info = BinaryInfo::from_cargo_subcommand(&cmd)?;
    println!("{}", info.to_string());

    let _bpf = BpfBuilder::new(PROBE)?
        .attach_probe("profile:hz:99", "profile")?
        .load()?;

    Ok(())
}
