pub use core::time::Duration;

#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct Instant(u64);

impl Instant {
    pub fn now() -> Self {
        Self(unsafe { bpf_helpers_sys::bpf_ktime_get_ns() })
    }

    pub fn duration_since(&self, earlier: Instant) -> Option<Duration> {
        if earlier > *self {
            return None;
        }
        Some(Duration::from_nanos(earlier.0 - self.0))
    }

    pub fn elapsed(&self) -> Duration {
        Instant::now()
            .duration_since(*self)
            .expect("now is later than self")
    }
}
