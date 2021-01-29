#![no_std]
#![no_main]

use bpf_helpers::{entry, map, program, sys, HashMap, U32};

program!(0xFFFF_FFFE, b"GPL");

#[derive(Debug, Clone, Copy, Eq, Hash, PartialEq)]
pub enum Config {
    Pid,
}

pub struct Frame {
    pub build_id: [u8; 20],
    pub offset: u64,
    pub depth: u8,
}

// TODO use array
#[map]
static CONFIG: HashMap<Config, U32> = HashMap::with_max_entries(1);
// TODO use per cpu lru map
#[map]
static FRAMES: HashMap<Frame, U32> = HashMap::with_max_entries(1024);
// TODO use array
#[map]
static STACK_TRACE: Array<sys::bpf_stack_build_id> = Array::with_max_entries(127);

#[entry("perf_event")]
fn profile(args: &bpf_perf_event_data) {
    let stack_size = unsafe {
        sys::bpf_get_stack(
            args as *const _ as *mut _,
            stack_trace.as_mut_ptr(),
            stack_trace.size(),
            (sys::BPF_F_USER_STACK | sys::BPF_F_USER_BUILD_ID) as _,
        )
    } as usize;
    for i in 0..stack_size {
        let frame = Frame {
            build_id: stack_trace[i].build_id,
            offset: unsafe { stack_trace[i].__bindgen_anon_1.offset },
            depth: (stack_size - i) as _,
        };
        let mut count = FRAMES.get(&frame).unwrap_or_default();
        count.set(count.get() + 1);
        FRAMES.insert(&frame, &count);
    }
}
