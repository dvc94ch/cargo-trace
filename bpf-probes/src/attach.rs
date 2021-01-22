use anyhow::{Context, Error, Result};
use libbpf_rs::Program;
use perf_event_open_sys::bindings::{perf_event_attr, perf_type_id_PERF_TYPE_TRACEPOINT};

#[derive(Debug, Eq, PartialEq)]
pub struct AttachedProbe(u32);

impl AttachedProbe {
    pub fn tracepoint(category: &str, name: &str) -> Result<Self> {
        let path = format!("/sys/kernel/debug/tracing/events/{}/{}/id", category, name);
        let event_id: u64 = std::fs::read_to_string(path)?.trim().parse()?;
        let mut attr: perf_event_attr = unsafe { std::mem::zeroed() };
        attr.config = event_id;
        attr.type_ = perf_type_id_PERF_TYPE_TRACEPOINT;
        Self::open(attr)
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
