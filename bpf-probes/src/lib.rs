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
use std::num::ParseIntError;
use std::path::PathBuf;
use std::time::Duration;
use thiserror::Error;

#[derive(Debug, Error)]
pub enum ProbeParseError {
    #[error("expected `{0}`")]
    Expected(&'static str),
    #[error("unsupported probe type `{0}`")]
    UnsupportedProbe(String),
    #[error("unsupported unit `{0}`")]
    UnsupportedUnit(String),
    #[error("{0}")]
    ParseInt(#[from] ParseIntError),
}

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

impl std::str::FromStr for Interval {
    type Err = ProbeParseError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        use ProbeParseError::*;
        let mut iter = s.splitn(2, ':');
        let unit = iter.next().ok_or(Expected("unit:value"))?;
        let value: u64 = iter.next().ok_or(Expected("unit:value"))?.parse()?;
        Ok(match unit {
            "hz" => Interval::Hz(value),
            "s" => Interval::Seconds(Duration::from_secs(value)),
            "ms" => Interval::Millis(Duration::from_millis(value)),
            "us" => Interval::Micros(Duration::from_micros(value)),
            _ => return Err(UnsupportedUnit(unit.to_string())),
        })
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

impl std::str::FromStr for Mode {
    type Err = ProbeParseError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        use ProbeParseError::*;
        let mut mode = Mode::default();
        for c in s.chars() {
            match c {
                'r' => {
                    mode.read = true;
                }
                'w' => {
                    mode.write = true;
                }
                'x' => {
                    mode.execute = true;
                }
                _ => {
                    return Err(Expected("rwx"));
                }
            }
        }
        Ok(mode)
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

impl std::str::FromStr for Probe {
    type Err = ProbeParseError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        use ProbeParseError::*;
        let mut iter = s.splitn(2, ':');
        let probe_ty = iter.next().ok_or(Expected("probe_type:probe_args"))?;
        let probe_args = iter.next().ok_or(Expected("probe_type:probe_args"))?;
        Ok(match probe_ty {
            "kprobe" => {
                let mut iter = probe_args.splitn(2, '+');
                let symbol = iter.next().ok_or(Expected("kprobe:symbol"))?.to_string();
                let offset = iter
                    .next()
                    .map(usize::from_str)
                    .transpose()?
                    .unwrap_or_default();
                Self::Kprobe { symbol, offset }
            }
            "kretprobe" => Self::Kretprobe {
                symbol: probe_args.to_string(),
            },
            "uprobe" => {
                let mut iter = probe_args.rsplitn(2, ':');
                let symbol = iter
                    .next()
                    .ok_or(Expected("uprobe:path:symbol"))?
                    .to_string();
                let path = iter
                    .next()
                    .ok_or(Expected("uprobe:path:symbol"))?
                    .to_string()
                    .into();

                let mut iter = symbol.splitn(2, '+');
                let symbol = iter.next().ok_or(Expected("kprobe:symbol"))?.to_string();
                let offset = iter
                    .next()
                    .map(usize::from_str)
                    .transpose()?
                    .unwrap_or_default();
                Self::Uprobe {
                    path,
                    symbol,
                    offset,
                }
            }
            "uretprobe" => {
                let mut iter = probe_args.rsplitn(2, ':');
                let symbol = iter
                    .next()
                    .ok_or(Expected("uretprobe:path:symbol"))?
                    .to_string();
                let path = iter
                    .next()
                    .ok_or(Expected("uretprobe:path:symbol"))?
                    .to_string()
                    .into();
                Self::Uretprobe { path, symbol }
            }
            "usdt" => {
                let mut iter = probe_args.rsplitn(2, ':');
                let probe = iter.next().ok_or(Expected("usdt:path:probe"))?.to_string();
                let path = iter
                    .next()
                    .ok_or(Expected("usdt:path:probe"))?
                    .to_string()
                    .into();
                Self::Usdt { path, probe }
            }
            "tracepoint" => {
                let mut iter = probe_args.splitn(2, ':');
                let category = iter
                    .next()
                    .ok_or(Expected("tracepoint:category:name"))?
                    .to_string();
                let name = iter
                    .next()
                    .ok_or(Expected("tracepoint:category:name"))?
                    .to_string();
                Self::Tracepoint { category, name }
            }
            "profile" => Self::Profile {
                interval: probe_args.parse()?,
            },
            "interval" => Self::Interval {
                interval: probe_args.parse()?,
            },
            "software" => {
                let mut iter = probe_args.splitn(2, ':');
                let event = iter
                    .next()
                    .ok_or(Expected("software:event:count"))?
                    .to_string();
                let count = iter
                    .next()
                    .ok_or(Expected("software:event:count"))?
                    .parse()?;
                Self::Software { event, count }
            }
            "hardware" => {
                let mut iter = probe_args.splitn(2, ':');
                let event = iter
                    .next()
                    .ok_or(Expected("hardware:event:count"))?
                    .to_string();
                let count = iter
                    .next()
                    .ok_or(Expected("hardware:event:count"))?
                    .parse()?;
                Self::Hardware { event, count }
            }
            "watchpoint" => {
                let mut iter = probe_args.splitn(3, ':');
                let address = iter
                    .next()
                    .ok_or(Expected("watchpoint:address:length:mode"))?;
                let length = iter
                    .next()
                    .ok_or(Expected("watchpoint:address:length:mode"))?
                    .parse()?;
                let mode = iter
                    .next()
                    .ok_or(Expected("watchpoint:address:length:mode"))?
                    .parse()?;
                let address = usize::from_str_radix(address.trim_start_matches("0x"), 16)?;
                Self::Watchpoint {
                    address,
                    length,
                    mode,
                }
            }
            "kfunc" => Self::Kfunc {
                func: probe_args.to_string(),
            },
            "kretfunc" => Self::Kretfunc {
                func: probe_args.to_string(),
            },
            _ => {
                return Err(UnsupportedProbe(probe_ty.to_string()));
            }
        })
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

    pub fn attach(&self, _program: &mut Program) -> Result<()> {
        /*match self {
            Self::Kprobe { symbol, offset } => {
                program.attach_kprobe(false, symbol)
            }
            Self::Kretprobe { symbol, offset } => program.attach_kprobe(true, symbol),
            Self::Tracepoint { category, name } => program.attach_tracepoint(category, name),
            Self::Profile { frequency } => {
                for cpu in get_online_cpus() {
                    program.attach_perf_event()
                }
            }
        }*/
        Ok(())
    }

    pub fn attach_pid(&self, _program: &mut Program, _pid: i32) -> Result<()> {
        /*match self {
            Self::Uprobe { path, symbol, offset } => program.attach_uprobe(false, pid, path, offset),
        }*/
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn probe_from_str() {
        let probes = [
            (
                "kprobe:finish_task_switch",
                Probe::Kprobe {
                    symbol: "finish_task_switch".into(),
                    offset: 0,
                },
            ),
            (
                "kprobe:finish_task_switch+8",
                Probe::Kprobe {
                    symbol: "finish_task_switch".into(),
                    offset: 8,
                },
            ),
            (
                "kretprobe:symbol",
                Probe::Kretprobe {
                    symbol: "symbol".into(),
                },
            ),
            (
                "uprobe:/path:symbol",
                Probe::Uprobe {
                    path: "/path".into(),
                    symbol: "symbol".into(),
                    offset: 0,
                },
            ),
            (
                "uprobe:/path:symbol+8",
                Probe::Uprobe {
                    path: "/path".into(),
                    symbol: "symbol".into(),
                    offset: 8,
                },
            ),
            (
                "uretprobe:/path:symbol",
                Probe::Uretprobe {
                    path: "/path".into(),
                    symbol: "symbol".into(),
                },
            ),
            (
                "tracepoint:category:name",
                Probe::Tracepoint {
                    category: "category".into(),
                    name: "name".into(),
                },
            ),
            (
                "profile:ms:100",
                Probe::Profile {
                    interval: Interval::Millis(Duration::from_millis(100)),
                },
            ),
            (
                "profile:hz:99",
                Probe::Profile {
                    interval: Interval::Hz(99),
                },
            ),
            (
                "watchpoint:0x10000:8:rwx",
                Probe::Watchpoint {
                    address: 0x10000,
                    length: 8,
                    mode: Mode {
                        read: true,
                        write: true,
                        execute: true,
                    },
                },
            ),
        ];
        for (s, p) in probes.iter() {
            let p2: Probe = s.parse().unwrap();
            assert_eq!(*p, p2);
            let p2: Probe = format!("{}", p2).parse().unwrap();
            assert_eq!(*p, p2);
        }
    }
}
