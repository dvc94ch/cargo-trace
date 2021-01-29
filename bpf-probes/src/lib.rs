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
use bpf_utils::elf::Elf;
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

#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub enum SoftwareEvent {
    AlignmentFaults,
    BpfOutput,
    ContextSwitches,
    CpuClock,
    CpuMigrations,
    Dummy,
    EmulationFaults,
    MajorFaults,
    MinorFaults,
    PageFaults,
    TaskClock,
}

impl SoftwareEvent {
    pub fn name(&self) -> &'static str {
        use SoftwareEvent::*;
        match self {
            AlignmentFaults => "alignment-faults",
            BpfOutput => "bpf-output",
            ContextSwitches => "context-switches",
            CpuClock => "cpu-clock",
            CpuMigrations => "cpu-migrations",
            Dummy => "dummy",
            EmulationFaults => "emulation-faults",
            MajorFaults => "major-faults",
            MinorFaults => "minor-faults",
            PageFaults => "page-faults",
            TaskClock => "task-clock",
        }
    }

    pub fn alias(&self) -> Option<&'static str> {
        use SoftwareEvent::*;
        match self {
            ContextSwitches => Some("cs"),
            CpuClock => Some("cpu"),
            PageFaults => Some("faults"),
            _ => None,
        }
    }

    pub fn default_count(&self) -> u64 {
        use SoftwareEvent::*;
        match self {
            ContextSwitches => 1_000,
            CpuClock => 1_000_000,
            MinorFaults => 100,
            PageFaults => 100,
            _ => 1,
        }
    }
}

impl std::fmt::Display for SoftwareEvent {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        write!(f, "{}", self.name())
    }
}

#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub enum HardwareEvent {
    BackendStalls,
    BranchInstructions,
    BranchMisses,
    BusCycles,
    CacheMisses,
    CacheReferences,
    CpuCycles,
    FrontendStalls,
    Instructions,
    RefCycles,
}

impl HardwareEvent {
    pub fn name(&self) -> &'static str {
        use HardwareEvent::*;
        match self {
            BackendStalls => "backend-stalls",
            BranchInstructions => "branch-instructions",
            BranchMisses => "branch-misses",
            BusCycles => "bus-cycles",
            CacheMisses => "cache-misses",
            CacheReferences => "cache-references",
            CpuCycles => "cpu-cycles",
            FrontendStalls => "frontend-stalls",
            Instructions => "instructions",
            RefCycles => "ref-cycles",
        }
    }

    pub fn alias(&self) -> Option<&'static str> {
        use HardwareEvent::*;
        match self {
            BranchInstructions => Some("branches"),
            CpuCycles => Some("cycles"),
            _ => None,
        }
    }

    pub fn default_count(&self) -> u64 {
        use HardwareEvent::*;
        match self {
            BranchInstructions => 100_000,
            BranchMisses => 100_000,
            BusCycles => 100_000,
            _ => 1_000_000,
        }
    }
}

impl std::fmt::Display for HardwareEvent {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        write!(f, "{}", self.name())
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
        event: SoftwareEvent,
        count: Option<u64>,
    },
    Hardware {
        event: HardwareEvent,
        count: Option<u64>,
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
            Software { event, count } => write!(
                f,
                "software:{}:{}",
                event,
                count.map(|c| c.to_string()).unwrap_or_default()
            ),
            Hardware { event, count } => write!(
                f,
                "hardware:{}:{}",
                event,
                count.map(|c| c.to_string()).unwrap_or_default()
            ),
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

    pub fn attach(&self, program: &mut Program) -> Result<Vec<AttachedProbe>> {
        let probes = match self {
            Self::Kprobe { symbol, offset } => vec![AttachedProbe::kprobe(symbol, *offset)?],
            Self::Kretprobe { symbol } => vec![AttachedProbe::kretprobe(symbol)?],
            Self::Uprobe {
                path,
                symbol,
                offset,
            } => {
                let elf = Elf::open(path)?;
                let address = elf.resolve_symbol(symbol, *offset)?.unwrap();
                vec![AttachedProbe::uprobe(path, address)?]
            }
            Self::Uretprobe { path, symbol } => {
                let elf = Elf::open(path)?;
                let address = elf.resolve_symbol(symbol, 0)?.unwrap();
                vec![AttachedProbe::uretprobe(path, address)?]
            }
            Self::Usdt { path, probe } => vec![AttachedProbe::usdt(path, probe)?],
            Self::Tracepoint { category, name } => vec![AttachedProbe::tracepoint(category, name)?],
            Self::Profile { interval } => AttachedProbe::profile(interval)?,
            Self::Interval { interval } => vec![AttachedProbe::interval(interval)?],
            Self::Software { event, count } => {
                let count = count.unwrap_or_else(|| event.default_count());
                vec![AttachedProbe::software(*event, count)?]
            }
            Self::Hardware { event, count } => {
                let count = count.unwrap_or_else(|| event.default_count());
                AttachedProbe::hardware(*event, count)?
            }
            Self::Watchpoint {
                address,
                length,
                mode,
            } => vec![AttachedProbe::watchpoint(*address, *length, *mode)?],
            Self::Kfunc { func } => vec![AttachedProbe::kfunc(func)?],
            Self::Kretfunc { func } => vec![AttachedProbe::kretfunc(func)?],
        };
        for probe in &probes {
            probe.set_bpf(program)?;
            probe.enable()?;
        }
        Ok(probes)
    }
}
