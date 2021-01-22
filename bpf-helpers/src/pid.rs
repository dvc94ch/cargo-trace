use byteorder::NativeEndian;
use zerocopy::byteorder::U64;

#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub struct PidTgid(U64<NativeEndian>);

impl PidTgid {
    pub fn current() -> Self {
        Self(U64::new(unsafe {
            bpf_helpers_sys::bpf_get_current_pid_tgid()
        }))
    }

    pub fn pid(&self) -> u32 {
        (self.0.get() >> 32) as _
    }

    pub fn tgid(&self) -> u32 {
        (self.0.get() & 0xf) as _
    }
}
