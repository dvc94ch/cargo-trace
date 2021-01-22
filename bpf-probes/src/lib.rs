//! rbpf
//!
//! 1. Write bpf program (bpf-helpers).
//! 2. Compile program to bpf (target bpf(el|eb)-unknown-none).
//! 3. Load bpf program (libbpf-rs).
//! 4. Attach probes (this crate)
//!    - the probe is created using the `perf_event_open` syscall.
//!    - the libbpf program is attached with `ioctl PERF_EVENT_IOC_SET_BPF`.
//! 5. Read bpf program maps (libbpf-rs).
use anyhow::Result;
use libbpf_rs::{Program, ProgramAttachType, ProgramType};
use std::path::PathBuf;
use std::time::Duration;

mod attach;
mod parse;

pub use crate::attach::AttachedProbe;

#[derive(Clone, Copy, Debug, Hash, PartialEq)]
pub enum Interval {
    Seconds(Duration),
    Millis(Duration),
    Micros(Duration),
    Hz(u64),
}

impl std::fmt::Display for Interval {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        use Interval::*;
        match self {
            Seconds(p) => write!(f, "s:{}", p.as_secs()),
            Millis(p) => write!(f, "ms:{}", p.as_millis()),
            Micros(p) => write!(f, "us:{}", p.as_micros()),
            Hz(freq) => write!(f, "hz:{}", freq),
        }
    }
}

#[derive(Clone, Copy, Debug, Default, Eq, Hash, PartialEq)]
pub struct Mode {
    read: bool,
    write: bool,
    execute: bool,
}

impl std::fmt::Display for Mode {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        if self.read {
            write!(f, "r")?;
        }
        if self.write {
            write!(f, "w")?;
        }
        if self.execute {
            write!(f, "x")?;
        }
        Ok(())
    }
}

#[derive(Clone, Debug, Hash, PartialEq)]
pub enum Probe {
    Kprobe {
        symbol: String,
        offset: usize,
    },
    Kretprobe {
        symbol: String,
    },
    Uprobe {
        path: PathBuf,
        symbol: String,
        offset: usize,
    },
    Uretprobe {
        path: PathBuf,
        symbol: String,
    },
    Usdt {
        path: PathBuf,
        probe: String,
    },
    Tracepoint {
        category: String,
        name: String,
    },
    Profile {
        interval: Interval,
    },
    Interval {
        interval: Interval,
    },
    Software {
        event: String,
        count: usize,
    },
    Hardware {
        event: String,
        count: usize,
    },
    Watchpoint {
        address: usize,
        length: usize,
        mode: Mode,
    },
    Kfunc {
        func: String,
    },
    Kretfunc {
        func: String,
    },
}

impl std::fmt::Display for Probe {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        use Probe::*;
        match self {
            Kprobe { symbol, offset } => write!(f, "kprobe:{}+{}", symbol, offset),
            Kretprobe { symbol } => write!(f, "kretprobe:{}", symbol),
            Uprobe {
                path,
                symbol,
                offset,
            } => write!(f, "uprobe:{}:{}+{}", path.display(), symbol, offset),
            Uretprobe { path, symbol } => write!(f, "uretprobe:{}:{}", path.display(), symbol),
            Usdt { path, probe } => write!(f, "usdt:{}:{}", path.display(), probe),
            Tracepoint { category, name } => write!(f, "tracepoint:{}:{}", category, name),
            Profile { interval } => write!(f, "profile:{}", interval),
            Interval { interval } => write!(f, "interval:{}", interval),
            Software { event, count } => write!(f, "software:{}:{}", event, count),
            Hardware { event, count } => write!(f, "hardware:{}:{}", event, count),
            Watchpoint {
                address,
                length,
                mode,
            } => write!(f, "watchpoint:{:x}:{}:{}", address, length, mode),
            Kfunc { func } => write!(f, "kfunc:{}", func),
            Kretfunc { func } => write!(f, "kretfunc:{}", func),
        }
    }
}

impl Probe {
    pub fn prog_type(&self) -> ProgramType {
        match self {
            Self::Kprobe { .. }
            | Self::Kretprobe { .. }
            | Self::Uprobe { .. }
            | Self::Uretprobe { .. }
            | Self::Usdt { .. } => ProgramType::Kprobe,
            Self::Tracepoint { .. } => ProgramType::Tracepoint,
            Self::Profile { .. }
            | Self::Interval { .. }
            | Self::Software { .. }
            | Self::Hardware { .. }
            | Self::Watchpoint { .. } => ProgramType::PerfEvent,
            Self::Kfunc { .. } | Self::Kretfunc { .. } => ProgramType::Tracing,
        }
    }

    pub fn attach_type(&self) -> Option<ProgramAttachType> {
        match self {
            Self::Kprobe { .. } | Self::Uprobe { .. } | Self::Usdt { .. } => {
                Some(ProgramAttachType::TraceFentry)
            }
            Self::Kretprobe { .. } | Self::Uretprobe { .. } => Some(ProgramAttachType::TraceFexit),
            _ => None,
        }
    }

    pub fn attach(&self, program: &mut Program) -> Result<AttachedProbe> {
        let probe = match self {
            Self::Tracepoint { category, name } => AttachedProbe::tracepoint(category, name),
            _ => todo!(),
        }?;
        probe.set_bpf(program)?;
        probe.enable()?;
        Ok(probe)
    }
}
