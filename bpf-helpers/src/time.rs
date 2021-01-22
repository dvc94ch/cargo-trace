use byteorder::NativeEndian;
use core::ops::{Add, AddAssign};
use zerocopy::byteorder::U64;
use zerocopy::{AsBytes, FromBytes, Unaligned};

#[derive(Clone, Copy, Debug, Default, Eq, Hash, PartialEq, AsBytes, FromBytes, Unaligned)]
#[repr(C)]
pub struct Duration(U64<NativeEndian>);

impl Duration {
    pub fn from_nanos(nanos: u64) -> Self {
        Self(U64::new(nanos))
    }

    pub fn as_nanos(&self) -> u64 {
        self.0.get()
    }
}

impl Add for Duration {
    type Output = Self;

    fn add(self, other: Self) -> Self {
        Self(U64::new(self.0.get() + other.0.get()))
    }
}

impl AddAssign for Duration {
    fn add_assign(&mut self, other: Self) {
        self.0.set(self.0.get() + other.0.get())
    }
}

#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq, AsBytes, FromBytes, Unaligned)]
#[repr(C)]
pub struct Instant(U64<NativeEndian>);

impl Instant {
    pub fn now() -> Self {
        Self(U64::new(unsafe { bpf_helpers_sys::bpf_ktime_get_ns() }))
    }

    pub fn duration_since(&self, earlier: Instant) -> Option<Duration> {
        if earlier.0.get() > self.0.get() {
            return None;
        }
        Some(Duration::from_nanos(self.0.get() - earlier.0.get()))
    }

    pub fn elapsed(&self) -> Duration {
        Instant::now()
            .duration_since(*self)
            .expect("now is later than self")
    }
}
