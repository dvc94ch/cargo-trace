//! eBPF maps.
//!
//! Maps are a generic data structure for storage of different types of data.
//! They allow sharing of data between eBPF kernel programs, and also between
//! kernel and user-space code.
use core::ffi::c_void;
use core::marker::PhantomData;
use core::mem;
use cty::c_int;

#[repr(transparent)]
pub struct RawMap<K, V, const T: u32> {
    def: bpf_helpers_sys::bpf_map_def,
    _marker: PhantomData<(K, V)>,
}

impl<K, V, const T: u32> RawMap<K, V, T> {
    /// Creates a map with the specified maximum number of elements.
    pub const fn with_max_entries(max_entries: usize) -> Self {
        Self {
            def: bpf_helpers_sys::bpf_map_def {
                type_: T,
                key_size: mem::size_of::<K>() as u32,
                value_size: mem::size_of::<V>() as u32,
                max_entries: max_entries as u32,
                map_flags: 0,
            },
            _marker: PhantomData,
        }
    }

    /// Returns a reference to the value corresponding to the key.
    ///
    /// To pass bpf validation the returned reference can be used only once.
    #[inline(always)]
    pub unsafe fn lookup(&self, key: &K) -> *mut V {
        bpf_helpers_sys::bpf_map_lookup_elem(
            &self.def as *const _ as *mut c_void,
            key as *const _ as *const c_void,
        ) as *mut V
    }

    /// Set the `value` in the map for `key`
    #[inline(always)]
    pub unsafe fn update(&self, key: &K, value: &V) {
        bpf_helpers_sys::bpf_map_update_elem(
            &self.def as *const _ as *mut c_void,
            key as *const _ as *const c_void,
            value as *const _ as *const c_void,
            bpf_helpers_sys::BPF_ANY.into(),
        );
    }

    /// Delete the entry indexed by `key`
    #[inline(always)]
    pub unsafe fn delete(&self, key: &K) {
        bpf_helpers_sys::bpf_map_delete_elem(
            &self.def as *const _ as *mut c_void,
            key as *const _ as *const c_void,
        );
    }
}

pub type HashMap<K, V> = RawMap<K, V, { bpf_helpers_sys::bpf_map_type_BPF_MAP_TYPE_HASH }>;
pub type PercpuHashMap<K, V> =
    RawMap<K, V, { bpf_helpers_sys::bpf_map_type_BPF_MAP_TYPE_PERCPU_HASH }>;
pub type LruHashMap<K, V> = RawMap<K, V, { bpf_helpers_sys::bpf_map_type_BPF_MAP_TYPE_LRU_HASH }>;
pub type LruPercpuHashMap<K, V> =
    RawMap<K, V, { bpf_helpers_sys::bpf_map_type_BPF_MAP_TYPE_LRU_PERCPU_HASH }>;

macro_rules! impl_hash_map {
    ($ty:ident) => {
        impl<K, V: Copy> $ty<K, V> {
            /// Returns a reference to the value corresponding to the key.
            #[inline(always)]
            pub fn get(&self, key: &K) -> Option<V> {
                let ptr = unsafe { self.lookup(key) };
                if ptr.is_null() {
                    None
                } else {
                    Some(unsafe { *ptr })
                }
            }

            /// Inserts the `value` in the map for `key`.
            #[inline(always)]
            pub fn insert(&self, key: &K, value: &V) {
                unsafe { self.update(key, value) }
            }

            /// Removes the entry indexed by `key`
            #[inline(always)]
            pub fn remove(&self, key: &K) {
                unsafe { self.delete(key) }
            }
        }
    };
}

impl_hash_map!(HashMap);
impl_hash_map!(PercpuHashMap);
impl_hash_map!(LruHashMap);
impl_hash_map!(LruPercpuHashMap);

pub type Array<V> = RawMap<u32, V, { bpf_helpers_sys::bpf_map_type_BPF_MAP_TYPE_ARRAY }>;
pub type PercpuArray<V> =
    RawMap<u32, V, { bpf_helpers_sys::bpf_map_type_BPF_MAP_TYPE_PERCPU_ARRAY }>;

macro_rules! impl_hash_map {
    ($ty:ident) => {
        impl<V: Copy> $ty<V> {
            /// Returns a reference to the value corresponding to the key.
            #[inline(always)]
            pub fn get(&self, key: u32) -> Option<V> {
                let ptr = unsafe { self.lookup(&key) };
                if ptr.is_null() {
                    None
                } else {
                    Some(unsafe { *ptr })
                }
            }

            /// Inserts the `value` in the map for `key`.
            #[inline(always)]
            pub fn insert(&self, key: u32, value: &V) {
                unsafe { self.update(&key, value) }
            }
        }
    };
}

impl_hash_map!(Array);
impl_hash_map!(PercpuArray);

/// Perf events map.
///
/// Perf events map that allows eBPF programs to store data in mmap()ed shared
/// memory accessible by user-space. This is a wrapper for
/// `BPF_MAP_TYPE_PERF_EVENT_ARRAY`.
pub type PerfEventArray =
    RawMap<u32, u32, { bpf_helpers_sys::bpf_map_type_BPF_MAP_TYPE_PERF_EVENT_ARRAY }>;
pub type RingBuf = RawMap<u32, u32, { bpf_helpers_sys::bpf_map_type_BPF_MAP_TYPE_RINGBUF }>;

macro_rules! impl_perf_event {
    ($ty:ident) => {
        impl $ty {
            // bpf_perf_event_read
            // bpf_perf_event_read_value

            #[inline(always)]
            pub fn perf_event_output<C, P>(&self, ctx: &C, data: &P, flags: u64) {
                unsafe {
                    bpf_helpers_sys::bpf_perf_event_output(
                        ctx as *const _ as *mut _,
                        &self.def as *const _ as *mut _,
                        flags,
                        data as *const _ as *mut c_void,
                        mem::size_of::<P>() as u64,
                    );
                }
            }
        }
    };
}

impl_perf_event!(PerfEventArray);
impl_perf_event!(RingBuf);

// TODO Use PERF_MAX_STACK_DEPTH
pub const BPF_MAX_STACK_DEPTH: usize = 127;

#[repr(C)]
pub struct BpfStackFrames {
    ip: [u64; BPF_MAX_STACK_DEPTH],
}

pub type StackTrace =
    RawMap<u32, BpfStackFrames, { bpf_helpers_sys::bpf_map_type_BPF_MAP_TYPE_STACK_TRACE }>;

impl StackTrace {
    pub const SKIP_FIELD_MASK: u64 = bpf_helpers_sys::BPF_F_SKIP_FIELD_MASK as _;
    pub const USER_STACK: u64 = bpf_helpers_sys::BPF_F_USER_STACK as _;
    pub const KERNEL_STACK: u64 = 0;
    pub const FAST_STACK_CMP: u64 = bpf_helpers_sys::BPF_F_FAST_STACK_CMP as _;
    pub const REUSE_STACKID: u64 = bpf_helpers_sys::BPF_F_REUSE_STACKID as _;

    #[inline(always)]
    pub fn stack_id(&self, ctx: *const c_void, flag: u64) -> Result<u32, c_int> {
        let ret = unsafe {
            bpf_helpers_sys::bpf_get_stackid(
                ctx as *mut _,
                &self.def as *const _ as *mut c_void,
                flag,
            )
        };
        if ret >= 0 {
            Ok(ret as _)
        } else {
            Err(ret)
        }
    }
}

/// Program array map.
///
/// An array of eBPF programs that can be used as a jump table.
///
/// To jump to a program, see the `tail_call` method.
pub type ProgArray = RawMap<u32, u32, { bpf_helpers_sys::bpf_map_type_BPF_MAP_TYPE_PROG_ARRAY }>;

impl ProgArray {
    /// Jump to the eBPF program referenced at `index`, passing `ctx` as context.
    ///
    /// This special method is used to trigger a "tail call", or in other words,
    /// to jump into another eBPF program.  The same stack frame is used (but
    /// values on stack and in registers for the caller are not accessible to
    /// the callee). This mechanism allows for program chaining, either for
    /// raising the maximum number of available eBPF instructions, or to execute
    /// given programs in conditional blocks. For security reasons, there is an
    /// upper limit to the number of successive tail calls that can be
    /// performed.
    ///
    /// If the call succeeds the kernel immediately runs the first instruction
    /// of the new program. This is not a function call, and it never returns to
    /// the previous program. If the call fails, then the helper has no effect,
    /// and the caller continues to run its subsequent instructions.
    ///
    /// A call can fail if the destination program for the jump does not exist
    /// (i.e. index is superior to the number of entries in the array), or
    /// if the maximum number of tail calls has been reached for this chain of
    /// programs.
    #[inline(always)]
    pub fn tail_call<C>(&mut self, ctx: &C, index: u32) -> Result<(), i32> {
        let ret = unsafe {
            bpf_helpers_sys::bpf_tail_call(
                ctx as *const _ as *mut _,
                &mut self.def as *mut _ as *mut c_void,
                index,
            )
        };
        if ret < 0 {
            return Err(ret);
        }
        Ok(())
    }
}
