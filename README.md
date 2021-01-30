# rust-bpf library (final name still pending)

This is a bpf library with a specific focus on building program analysis tools for rust
programs. Most of the code is very generic so it can be easily adapted for other bpf use
cases. Supports most probe types supported by `bpftrace`.

## Example
Create a bpf program in rust that counts user stack traces.

```rust
#![no_std]
#![no_main]

use bpf_helpers::{entry, map, program, HashMap, StackTrace, U32};

program!(0xFFFF_FFFE, b"GPL");

#[map]
static USER_COUNT: HashMap<U32, U32> = HashMap::with_max_entries(1024);
#[map]
static USER_STACKS: StackTrace = StackTrace::with_max_entries(1024);

#[entry("perf_event")]
fn profile(args: &bpf_perf_event_data) {
    if let Ok(uid) = USER_STACKS.stack_id(args as *const _ as *const _, StackTrace::USER_STACK) {
        let mut count = USER_COUNT.get(&U32::new(uid)).unwrap_or_default();
        count.set(count.get() + 1);
        USER_COUNT.insert(&U32::new(uid), &count);
    }
}
```

Make a program that loads the bpf program and reads/post-processes it's data.

```rust
use anyhow::Result;
use bpf::utils::BinaryInfo;
use bpf::{BpfBuilder, U32};
use cargo_subcommand::Subcommand;

static PROBE: &[u8] = include_bytes!(concat!(
    env!("OUT_DIR"),
    "/target/bpf/programs/rust-analysis-probe/rust-analysis-probe.elf",
));

fn main() -> Result<()> {
    // needs to be root to use bpf
    bpf::utils::escalate_if_needed().unwrap();

    // parse cli
    let cmd = Subcommand::new(std::env::args(), "flamegraph", |_, _| Ok(false))?;

    // use binary info to locate libraries and debug info
    let info = BinaryInfo::from_cargo_subcommand(&cmd)?;

    // start and pause the child process
    let pid = info.spawn()?;

    // load a bpf program and attach it to a probe
    let mut bpf = BpfBuilder::new(PROBE)?
        .set_child_pid(pid)
        .attach_probe("profile:hz:99", "profile")?
        .load()?;

    // continue child process and wait for it to exit
    pid.cont_and_wait()?;

    // post process the data created by the bpf program
    let user_count = bpf
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
    }

    Ok(())
}
```

## License
MIT OR Apache-2.0
