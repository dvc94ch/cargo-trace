use anyhow::Result;
use bpf::utils::{ehframe, escalate_if_needed, BinaryInfo};
use bpf::{BpfBuilder, I32, U16, U32, U64};
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
    escalate_if_needed().unwrap();
    env_logger::init();
    let args = std::env::args();
    let cmd = Subcommand::new(args, "trace", |_, _| Ok(true))?;
    let status = Command::new("cargo")
        .arg("build")
        .args(cmd.args())
        .spawn()?
        .wait()?;
    if !status.success() {
        std::process::exit(status.code().unwrap());
    }
    let info = BinaryInfo::from_cargo_subcommand(&cmd)?;
    let table = info.elf().unwind_table()?;
    log::debug!("{}", info.to_string());
    log::debug!("size of unwind table {}", table.rows.len());
    let mut ehframe = std::fs::OpenOptions::new()
        .write(true)
        .truncate(true)
        .create(true)
        .open(".ehframe")?;
    ehframe.write_all(table.to_string().as_bytes())?;
    let pid = info.spawn()?;

    // TODO: load entire memory map
    let mut addr = [0u8; 12];
    let mut map = std::fs::File::open(format!("/proc/{}/maps", u32::from(pid)))?;
    map.read_exact(&mut addr)?;
    let offset = u64::from_str_radix(std::str::from_utf8(&addr)?, 16)?;
    log::debug!("loading program with pid {}", u32::from(pid));
    log::debug!("load address is 0x{:x}", offset);

    let bpf_entry = if cmd.cmd().starts_with("profile:") {
        "profile"
    } else {
        "kprobe"
    };
    let probe = if cmd.cmd().starts_with("uprobe:") {
        let parts = cmd.cmd().split(':').collect::<Vec<_>>();
        if parts.len() == 2 {
            format!("uprobe:{}:{}", info.path().display(), parts[1])
        } else {
            cmd.cmd().to_string()
        }
    } else {
        cmd.cmd().to_string()
    };
    let mut bpf = BpfBuilder::new(PROBE)?
        .set_child_pid(pid)
        .attach_probe(&probe, bpf_entry)?
        .load()?;

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
    let mut len = bpf.array::<U32>("ARRAY_SIZE")?;
    len.insert(&U32::new(0), &U32::new(table.rows.len() as _))?;

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
