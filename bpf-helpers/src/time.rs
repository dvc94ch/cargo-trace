use core::ops::{Add, AddAssign};

#[derive(Clone, Copy, Debug, Default, Eq, Hash, PartialEq)]
#[repr(C)]
pub struct Duration(u64);

impl Duration {
    pub fn from_nanos(nanos: u64) -> Self {
        Self(nanos)
    }

    pub fn as_nanos(&self) -> u64 {
        self.0
    }
}

impl Add for Duration {
    type Output = Self;

    fn add(self, other: Self) -> Self {
        Self(self.0 + other.0)
    }
}

impl AddAssign for Duration {
    fn add_assign(&mut self, other: Self) {
        self.0 += other.0;
    }
}

#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
#[repr(C)]
pub struct Instant(u64);

impl Instant {
    pub fn now() -> Self {
        Self(unsafe { bpf_helpers_sys::bpf_ktime_get_ns() })
    }

    pub fn duration_since(&self, earlier: Instant) -> Option<Duration> {
        if earlier.0 > self.0 {
            return None;
        }
        Some(Duration::from_nanos(self.0 - earlier.0))
    }

    pub fn elapsed(&self) -> Duration {
        Instant::now()
            .duration_since(*self)
            .expect("now is later than self")
    }
}
