use anyhow::Result;
use bpf::utils::{ehframe, sudo, BinaryInfo};
use bpf::{BpfBuilder, Probe, ProgramType, I32, U16, U32, U64};
use cargo_subcommand::Subcommand;
use std::io::{Read, Write};
use std::process::Command;
use zerocopy::{AsBytes, FromBytes, Unaligned};

static PROBE: &[u8] = include_bytes!(concat!(
    env!("OUT_DIR"),
    "/target/bpf/programs/cargo-trace-probe/cargo-trace-probe.elf",
));

#[derive(Clone, Copy, AsBytes, FromBytes, Unaligned)]
#[repr(C)]
pub struct Instruction {
    op: u8,
    reg: u8,
    _padding: U16,
    offset: I32,
}

impl From<ehframe::format::Instruction> for Instruction {
    fn from(ins: ehframe::format::Instruction) -> Self {
        Self {
            op: ins.op() as _,
            reg: ins.reg(),
            _padding: U16::new(0),
            offset: I32::new(ins.offset()),
        }
    }
}

fn main() -> Result<()> {
    env_logger::init();
    let args = std::env::args();
    let cmd = Subcommand::new(args, "trace", |_, _| Ok(true))?;
    if sudo::check() == sudo::RunningAs::User {
        let status = Command::new("cargo")
            .arg("build")
            .args(cmd.args())
            .spawn()?
            .wait()?;
        if !status.success() {
            std::process::exit(status.code().unwrap());
        }
    }
    sudo::with_env(&["RUST_LOG"]).unwrap();

    let info = BinaryInfo::from_cargo_subcommand(&cmd)?;
    let table = info.elf().unwind_table()?;
    log::debug!("\n{}", info.to_string());
    log::debug!("size of unwind table {}", table.rows.len());
    let mut ehframe = std::fs::OpenOptions::new()
        .write(true)
        .truncate(true)
        .create(true)
        .open(".ehframe")?;
    ehframe.write_all(table.to_string().as_bytes())?;
    let pid = info.spawn()?;
    log::debug!("loading program with pid {}", u32::from(pid));

    // TODO: load entire memory map
    let mut addr = [0u8; 12];
    let mut map = std::fs::File::open(format!("/proc/{}/maps", u32::from(pid)))?;
    map.read_exact(&mut addr)?;
    let offset = u64::from_str_radix(std::str::from_utf8(&addr)?, 16)?;
    log::debug!("load address is 0x{:x}", offset);

    // TODO more convenience:
    // user symbols lookup where demangled == provided
    // convert tracepoint to kprobes on syscalls
    let mut probe: Probe = cmd.cmd().parse()?;
    let entry = match probe.prog_type() {
        ProgramType::Kprobe => "kprobe",
        ProgramType::PerfEvent => "perf_event",
        _ => return Err(anyhow::anyhow!("unsupported probe {}", probe)),
    };
    log::debug!("setting default path to {}", info.path().display());
    probe.set_default_path(info.path());
    let mut bpf = BpfBuilder::new(PROBE)?.attach_probe(probe, entry)?.load()?;
    log::debug!("loaded bpf program");

    let mut pc = bpf.array::<U64>("PC")?;
    for (i, row) in table.rows.iter().enumerate() {
        pc.insert(
            &U32::new(i as _),
            &U64::new(row.start_address as u64 + offset),
        )?;
    }
    let mut rip = bpf.array::<Instruction>("RIP")?;
    for (i, row) in table.rows.iter().enumerate() {
        rip.insert(&U32::new(i as _), &row.ra.gen().into())?;
    }
    let mut rsp = bpf.array::<Instruction>("RSP")?;
    for (i, row) in table.rows.iter().enumerate() {
        rsp.insert(&U32::new(i as _), &row.cfa.gen().into())?;
    }
    let mut rbp = bpf.array::<Instruction>("RBP")?;
    for (i, row) in table.rows.iter().enumerate() {
        rbp.insert(&U32::new(i as _), &row.rbp.gen().into())?;
    }
    let mut rbx = bpf.array::<Instruction>("RBX")?;
    for (i, row) in table.rows.iter().enumerate() {
        rbx.insert(&U32::new(i as _), &row.rbx.gen().into())?;
    }
    let mut len = bpf.array::<U32>("CONFIG")?;
    len.insert(&U32::new(0), &U32::new(table.rows.len() as _))?;
    len.insert(&U32::new(1), &U32::new(pid.into()))?;

    log::debug!("running program");
    pid.cont_and_wait()?;

    // TODO create a flamegraph
    let user_stack = bpf.hash_map::<[U64; 4], U32>("USER_STACK")?;
    for (stack, count) in user_stack.iter() {
        println!("stack observed {} times:", count);
        for (i, ip) in stack.iter().enumerate() {
            if ip.get() == 0 {
                break;
            }
            let ip = ip.get() - offset;
            info.print_frame(i, ip as usize)?;
        }
    }

    Ok(())
}
