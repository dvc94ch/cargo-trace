use crate::{HardwareEvent, Interval, Mode, SoftwareEvent};
use anyhow::{Context, Error, Result};
use libbpf_rs::Program;
use perf_event_open_sys::bindings::{self as sys, perf_event_attr};
use std::ffi::CString;
use std::path::Path;
use std::str::FromStr;

#[derive(Debug, Eq, PartialEq)]
pub struct AttachedProbe(u32);

impl AttachedProbe {
    pub fn kprobe(symbol: &str, offset: usize) -> Result<Self> {
        let symbol = CString::new(symbol)?;
        let mut attr: perf_event_attr = unsafe { std::mem::zeroed() };
        attr.type_ = pmu_type("kprobe")?;
        attr.config = 0;
        attr.__bindgen_anon_3 = sys::perf_event_attr__bindgen_ty_3 {
            kprobe_func: symbol.as_ptr() as _,
        };
        attr.__bindgen_anon_4 = sys::perf_event_attr__bindgen_ty_4 {
            probe_offset: offset as _,
        };
        Self::open_for_any_cpu(&attr)
    }

    pub fn kretprobe(symbol: &str) -> Result<Self> {
        let symbol = CString::new(symbol)?;
        let mut attr: perf_event_attr = unsafe { std::mem::zeroed() };
        attr.type_ = pmu_type("kprobe")?;
        attr.config = 1;
        attr.__bindgen_anon_3 = sys::perf_event_attr__bindgen_ty_3 {
            kprobe_func: symbol.as_ptr() as _,
        };
        attr.__bindgen_anon_4 = sys::perf_event_attr__bindgen_ty_4 { probe_offset: 0 };
        Self::open_for_any_cpu(&attr)
    }

    pub fn uprobe(_path: &Path, _symbol: &str, _offset: usize) -> Result<Self> {
        todo!()
    }

    pub fn uretprobe(_path: &Path, _symbol: &str) -> Result<Self> {
        todo!()
    }

    pub fn usdt(_path: &Path, _probe: &str) -> Result<Self> {
        todo!()
    }

    pub fn tracepoint(category: &str, name: &str) -> Result<Self> {
        let path = format!("/sys/kernel/debug/tracing/events/{}/{}/id", category, name);
        let mut attr: perf_event_attr = unsafe { std::mem::zeroed() };
        attr.type_ = pmu_type("tracepoint")?;
        attr.config = read(&path)?;
        Self::open_for_any_cpu(&attr)
    }

    pub fn profile(interval: &Interval) -> Result<Vec<Self>> {
        let mut attr: perf_event_attr = unsafe { std::mem::zeroed() };
        attr.type_ = sys::perf_type_id_PERF_TYPE_SOFTWARE;
        attr.config = sys::perf_sw_ids_PERF_COUNT_SW_CPU_CLOCK as _;
        match interval {
            Interval::Seconds(p) => {
                attr.__bindgen_anon_1 = sys::perf_event_attr__bindgen_ty_1 {
                    sample_period: p.as_nanos() as _,
                };
            }
            Interval::Millis(p) => {
                attr.__bindgen_anon_1 = sys::perf_event_attr__bindgen_ty_1 {
                    sample_period: p.as_nanos() as _,
                };
            }
            Interval::Micros(p) => {
                attr.__bindgen_anon_1 = sys::perf_event_attr__bindgen_ty_1 {
                    sample_period: p.as_nanos() as _,
                };
            }
            Interval::Hz(f) => {
                attr.set_freq(1);
                attr.__bindgen_anon_1 = sys::perf_event_attr__bindgen_ty_1 { sample_freq: *f };
            }
        }
        Self::open_for_every_cpu(&attr)
    }

    pub fn interval(interval: &Interval) -> Result<Self> {
        let mut attr: perf_event_attr = unsafe { std::mem::zeroed() };
        attr.type_ = sys::perf_type_id_PERF_TYPE_SOFTWARE;
        attr.config = sys::perf_sw_ids_PERF_COUNT_SW_CPU_CLOCK as _;
        match interval {
            Interval::Seconds(p) => {
                attr.__bindgen_anon_1 = sys::perf_event_attr__bindgen_ty_1 {
                    sample_period: p.as_nanos() as _,
                };
            }
            Interval::Millis(p) => {
                attr.__bindgen_anon_1 = sys::perf_event_attr__bindgen_ty_1 {
                    sample_period: p.as_nanos() as _,
                };
            }
            Interval::Micros(p) => {
                attr.__bindgen_anon_1 = sys::perf_event_attr__bindgen_ty_1 {
                    sample_period: p.as_nanos() as _,
                };
            }
            Interval::Hz(f) => {
                attr.set_freq(1);
                attr.__bindgen_anon_1 = sys::perf_event_attr__bindgen_ty_1 { sample_freq: *f };
            }
        }
        Self::open_for_any_cpu(&attr)
    }

    pub fn software(event: SoftwareEvent, count: u64) -> Result<Self> {
        use SoftwareEvent::*;
        let mut attr: perf_event_attr = unsafe { std::mem::zeroed() };
        attr.type_ = sys::perf_type_id_PERF_TYPE_SOFTWARE;
        attr.config = match event {
            AlignmentFaults => sys::perf_sw_ids_PERF_COUNT_SW_ALIGNMENT_FAULTS,
            BpfOutput => sys::perf_sw_ids_PERF_COUNT_SW_BPF_OUTPUT,
            ContextSwitches => sys::perf_sw_ids_PERF_COUNT_SW_CONTEXT_SWITCHES,
            CpuClock => sys::perf_sw_ids_PERF_COUNT_SW_CPU_CLOCK,
            CpuMigrations => sys::perf_sw_ids_PERF_COUNT_SW_CPU_MIGRATIONS,
            Dummy => sys::perf_sw_ids_PERF_COUNT_SW_DUMMY,
            EmulationFaults => sys::perf_sw_ids_PERF_COUNT_SW_EMULATION_FAULTS,
            MajorFaults => sys::perf_sw_ids_PERF_COUNT_SW_PAGE_FAULTS_MAJ,
            MinorFaults => sys::perf_sw_ids_PERF_COUNT_SW_PAGE_FAULTS_MIN,
            PageFaults => sys::perf_sw_ids_PERF_COUNT_SW_PAGE_FAULTS,
            TaskClock => sys::perf_sw_ids_PERF_COUNT_SW_TASK_CLOCK,
        } as _;
        attr.__bindgen_anon_1 = sys::perf_event_attr__bindgen_ty_1 {
            sample_period: count,
        };
        Self::open_for_any_cpu(&attr)
    }

    pub fn hardware(event: HardwareEvent, count: u64) -> Result<Vec<Self>> {
        use HardwareEvent::*;
        let mut attr: perf_event_attr = unsafe { std::mem::zeroed() };
        attr.type_ = sys::perf_type_id_PERF_TYPE_HARDWARE;
        attr.config = match event {
            BackendStalls => sys::perf_hw_id_PERF_COUNT_HW_STALLED_CYCLES_BACKEND,
            BranchInstructions => sys::perf_hw_id_PERF_COUNT_HW_BRANCH_INSTRUCTIONS,
            BranchMisses => sys::perf_hw_id_PERF_COUNT_HW_BRANCH_MISSES,
            BusCycles => sys::perf_hw_id_PERF_COUNT_HW_BUS_CYCLES,
            CacheMisses => sys::perf_hw_id_PERF_COUNT_HW_CACHE_MISSES,
            CacheReferences => sys::perf_hw_id_PERF_COUNT_HW_CACHE_REFERENCES,
            CpuCycles => sys::perf_hw_id_PERF_COUNT_HW_CPU_CYCLES,
            FrontendStalls => sys::perf_hw_id_PERF_COUNT_HW_STALLED_CYCLES_FRONTEND,
            Instructions => sys::perf_hw_id_PERF_COUNT_HW_INSTRUCTIONS,
            RefCycles => sys::perf_hw_id_PERF_COUNT_HW_REF_CPU_CYCLES,
        } as _;
        attr.__bindgen_anon_1 = sys::perf_event_attr__bindgen_ty_1 {
            sample_period: count,
        };
        Self::open_for_every_cpu(&attr)
    }

    pub fn watchpoint(_address: usize, _length: usize, _mode: Mode) -> Result<Self> {
        todo!()
    }

    pub fn kfunc(_func: &str) -> Result<Self> {
        todo!()
    }

    pub fn kretfunc(_func: &str) -> Result<Self> {
        todo!()
    }

    fn open_for_every_cpu(attr: &perf_event_attr) -> Result<Vec<Self>> {
        bpf_utils::cpu::online_cpu_ids()?
            .into_iter()
            .map(|cpu| Self::open_for_cpu(attr, cpu as _))
            .collect()
    }

    fn open_for_any_cpu(attr: &perf_event_attr) -> Result<Self> {
        Self::open_for_cpu(attr, 0)
    }

    fn open_for_cpu(attr: &perf_event_attr, cpu: i32) -> Result<Self> {
        let pid = -1;
        let group_fd = -1;
        let pfd = unsafe {
            perf_event_open_sys::perf_event_open(
                attr as *const _ as *mut _,
                pid,
                cpu,
                group_fd,
                perf_event_open_sys::bindings::PERF_FLAG_FD_CLOEXEC as _,
            )
        };
        if pfd < 0 {
            return Err(std::io::Error::last_os_error().into());
        }
        Ok(Self(pfd as _))
    }

    pub fn enable(&self) -> Result<()> {
        if unsafe { perf_event_open_sys::ioctls::ENABLE(self.0 as _, 0) } != 0 {
            return Err(Error::from(std::io::Error::last_os_error()))
                .context("ioctl(PERF_EVENT_IOC_ENABLE)");
        }
        Ok(())
    }

    pub fn disable(&self) -> Result<()> {
        if unsafe { perf_event_open_sys::ioctls::DISABLE(self.0 as _, 0) } != 0 {
            return Err(Error::from(std::io::Error::last_os_error()))
                .context("ioctl(PERF_EVENT_IOC_DISABLE)");
        }
        Ok(())
    }

    pub fn set_bpf(&self, program: &Program) -> Result<()> {
        if unsafe { perf_event_open_sys::ioctls::SET_BPF(self.0 as _, program.fd() as _) } != 0 {
            return Err(Error::from(std::io::Error::last_os_error()))
                .context("ioctl(PERF_EVENT_IOC_SET_BPF)");
        }
        Ok(())
    }

    fn close(&self) -> Result<()> {
        if unsafe { libc::close(self.0 as _) } < 0 {
            return Err(Error::from(std::io::Error::last_os_error()))
                .context("close perf event FD failed");
        }
        Ok(())
    }
}

impl Drop for AttachedProbe {
    fn drop(&mut self) {
        if let Err(err) = self.disable() {
            log::warn!("{}", err);
        }
        if let Err(err) = self.close() {
            log::warn!("{}", err);
        }
    }
}

fn pmu_type(event: &str) -> Result<u32> {
    let path = format!("/sys/bus/event_source/devices/{}/type", event);
    read(&path)
}

fn read<P, T>(path: P) -> Result<T>
where
    P: AsRef<Path>,
    T: FromStr,
    T::Err: std::error::Error + Send + Sync + 'static,
{
    Ok(std::fs::read_to_string(path)?.trim().parse()?)
}
