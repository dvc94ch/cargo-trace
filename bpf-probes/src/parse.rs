use crate::{Interval, Mode, Probe};
use std::num::ParseIntError;
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
