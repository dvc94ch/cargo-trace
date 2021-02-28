use anyhow::Result;
use bpf::utils::{ehframe, sudo, BinaryInfo};
use bpf::{BpfBuilder, Probe, ProgramType, I64, U32, U64};
use cargo_subcommand::Subcommand;
use inferno::flamegraph::{self, Options};
use std::fs::{File, OpenOptions};
use std::io::{BufRead, BufReader, Write};
use std::process::Command;
use zerocopy::{AsBytes, FromBytes, Unaligned};

static PROBE: &[u8] = include_bytes!(concat!(
    env!("OUT_DIR"),
    "/target/bpf/programs/cargo-trace-probe/cargo-trace-probe.elf",
));

#[derive(Clone, Copy, AsBytes, FromBytes, Unaligned)]
#[repr(C)]
pub struct Instruction {
    op: U64,
    offset: I64,
}

impl From<ehframe::Instruction> for Instruction {
    fn from(ins: ehframe::Instruction) -> Self {
        Self {
            op: U64::new(match (ins.op(), ins.reg()) {
                (ehframe::Op::CfaOffset, None) => 1,
                (ehframe::Op::Register, Some(ehframe::Reg::Rip)) => 2,
                (ehframe::Op::Register, Some(ehframe::Reg::Rsp)) => 3,
                _ => 0,
            }),
            offset: I64::new(ins.offset().unwrap_or_default()),
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
    let uid = unsafe { libc::getuid() };
    sudo::with_env(&["RUST_LOG"]).unwrap();

    let mut info = BinaryInfo::from_cargo_subcommand(&cmd)?;

    // TODO more convenience:
    // uprobes: find path from libname
    // tracepoint: convert to kprobes on syscalls
    let mut probe: Probe = cmd.cmd().parse()?;
    let entry = match probe.prog_type() {
        ProgramType::Kprobe => "kprobe",
        ProgramType::PerfEvent => "perf_event",
        _ => return Err(anyhow::anyhow!("unsupported probe {}", probe)),
    };
    log::debug!("setting default path to {}", info.path().display());
    probe.set_default_path(info.path());
    let mut builder = BpfBuilder::new(PROBE)?;
    if let ProgramType::PerfEvent = probe.prog_type() {
        // without this we will get kernel regs instead of user regs.
        builder.set_child_pid(info.pid());
    }
    builder.attach_probe(probe, entry)?;
    let mut bpf = builder.load()?;
    log::debug!("loaded bpf program");

    let mut i = 0;
    for binary in info.iter() {
        let table = binary.elf.unwind_table()?;
        for row in table.rows.iter() {
            let addr = binary.start_addr + row.start_address;
            let mut pc = bpf.array::<U64>("PC")?;
            pc.insert(&U32::new(i as _), &U64::new(addr as _))?;

            let mut rip = bpf.array::<Instruction>("RIP")?;
            rip.insert(&U32::new(i as _), &row.rip.into())?;

            let mut rsp = bpf.array::<Instruction>("RSP")?;
            rsp.insert(&U32::new(i as _), &row.rsp.into())?;

            i += 1;
        }
    }
    let mut len = bpf.array::<U32>("CONFIG")?;
    len.insert(&U32::new(0), &U32::new(i as _))?;
    len.insert(&U32::new(1), &U32::new(info.pid()))?;

    log::debug!("running program");
    info.cont()?;

    unsafe { libc::setuid(uid) };
    let user_stack = bpf.hash_map::<[U64; 48], U32>("USER_STACK")?;

    write_flamegraph(&info, user_stack.iter(), cmd.cmd().to_string())?;

    Ok(())
}

fn write_flamegraph(
    info: &BinaryInfo,
    iter: impl Iterator<Item = ([U64; 48], U32)>,
    title: String,
) -> Result<()> {
    let mut f = OpenOptions::new()
        .create(true)
        .truncate(true)
        .write(true)
        .open("collapsed.txt")?;

    let mut symbols = Vec::with_capacity(48);
    for (stack, count) in iter {
        symbols.clear();
        for ip in stack.iter() {
            let ip = ip.get() as usize;
            if ip == 0 {
                break;
            }
            if let Some(symbol) = info.resolve_symbol(ip)? {
                symbols.push(symbol);
            } else {
                break;
            }
        }
        symbols.reverse();
        let mut collapsed = symbols.join(";");
        collapsed.push(' ');
        collapsed.push_str(&count.to_string());
        writeln!(f, "{}", collapsed)?;
    }

    let collapsed = BufReader::new(File::open("collapsed.txt")?)
        .lines()
        .collect::<Result<Vec<_>, _>>()?;
    let f = OpenOptions::new()
        .create(true)
        .truncate(true)
        .write(true)
        .open("flamegraph.svg")?;
    let mut options = Options::default();
    options.title = title;
    flamegraph::from_lines(&mut options, collapsed.iter().map(|s| s.as_str()), f)?;
    Ok(())
}
