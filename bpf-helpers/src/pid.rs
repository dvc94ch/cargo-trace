#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub struct PidTgid(u64);

impl PidTgid {
    pub fn current() -> Self {
        Self(unsafe { bpf_helpers_sys::bpf_get_current_pid_tgid() })
    }

    pub fn pid(&self) -> u32 {
        (self.0 >> 32) as _
    }

    pub fn tgid(&self) -> u32 {
        (self.0 & 0xf) as _
    }
}
