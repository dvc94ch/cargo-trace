use anyhow::Result;
use bpf::utils::{ehframe, sudo, AddressMap, BinaryInfo, Elf};
use bpf::{BpfBuilder, Probe, ProgramType, I32, U16, U32, U64};
use cargo_subcommand::Subcommand;
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

impl From<ehframe::Instruction> for Instruction {
    fn from(ins: ehframe::Instruction) -> Self {
        Self {
            op: match ins.op() {
                ehframe::Op::Unimplemented => 0,
                ehframe::Op::Undefined => 1,
                ehframe::Op::CfaOffset => 2,
                ehframe::Op::Register => 3,
                ehframe::Op::PltExpr => 0,
            },
            reg: match ins.reg() {
                Some(ehframe::Reg::Rip) => 1,
                Some(ehframe::Reg::Rsp) => 2,
                Some(ehframe::Reg::Rbp) => 3,
                Some(ehframe::Reg::Rbx) => 4,
                None => 0,
            },
            _padding: U16::new(0),
            offset: I32::new(ins.offset().unwrap_or_default() as _),
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
    log::debug!("\n{}", info.to_string());
    let pid = info.spawn()?;
    log::debug!("loading program with pid {}", u32::from(pid));
    let map = AddressMap::load_pid(u32::from(pid))?;

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
    let mut bpf = BpfBuilder::new(PROBE)?
        .set_child_pid(pid) // without this we will get kernel ip
        .attach_probe(probe, entry)?
        .load()?;
    log::debug!("loaded bpf program");

    let mut i = 0;
    for entry in map.iter() {
        let table = Elf::open(&entry.path)?.unwind_table()?;
        for row in table.rows.iter() {
            let addr = entry.start_addr + row.start_address;
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
    len.insert(&U32::new(1), &U32::new(pid.into()))?;

    log::debug!("running program");
    pid.cont_and_wait()?;

    // TODO create a flamegraph
    let user_stack = bpf.hash_map::<[U64; 24], U32>("USER_STACK")?;
    for (stack, count) in user_stack.iter() {
        println!("stack observed {} times:", count);
        for (i, ip) in stack.iter().enumerate() {
            let mut ip = ip.get() as usize;
            if ip == 0 {
                break;
            }
            if let Some(entry) = map.entry(ip) {
                ip -= entry.start_addr;
            }
            info.print_frame(i, ip as usize)?;
        }
    }

    Ok(())
}
