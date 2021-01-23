use crate::{Interval, Mode};
use anyhow::{Context, Error, Result};
use libbpf_rs::Program;
use perf_event_open_sys::bindings::{
    perf_event_attr, perf_event_attr__bindgen_ty_3, perf_event_attr__bindgen_ty_4,
};
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
        attr.__bindgen_anon_3 = perf_event_attr__bindgen_ty_3 {
            kprobe_func: symbol.as_ptr() as _,
        };
        attr.__bindgen_anon_4 = perf_event_attr__bindgen_ty_4 {
            probe_offset: offset as _,
        };
        Self::open(attr)
    }

    pub fn kretprobe(symbol: &str) -> Result<Self> {
        let symbol = CString::new(symbol)?;
        let mut attr: perf_event_attr = unsafe { std::mem::zeroed() };
        attr.type_ = pmu_type("kprobe")?;
        attr.config = 1;
        attr.__bindgen_anon_3 = perf_event_attr__bindgen_ty_3 {
            kprobe_func: symbol.as_ptr() as _,
        };
        attr.__bindgen_anon_4 = perf_event_attr__bindgen_ty_4 { probe_offset: 0 };
        Self::open(attr)
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
        Self::open(attr)
    }

    pub fn profile(_interval: &Interval) -> Result<Self> {
        todo!()
    }

    pub fn interval(_interval: &Interval) -> Result<Self> {
        todo!()
    }

    pub fn software(_event: &str, _count: usize) -> Result<Self> {
        todo!()
    }

    pub fn hardware(_event: &str, _count: usize) -> Result<Self> {
        todo!()
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

    fn open(mut attr: perf_event_attr) -> Result<Self> {
        let pid = -1;
        let cpu = 0;
        let group_fd = -1;
        let pfd = unsafe {
            perf_event_open_sys::perf_event_open(
                &mut attr as *mut _,
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
