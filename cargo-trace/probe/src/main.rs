#![no_std]
#![no_main]

use bpf_helpers::{entry, map, program, Array, HashMap};

program!(0xFFFF_FFFE, b"GPL");

const MAX_STACK_DEPTH: usize = 20;
const EHFRAME_ENTRIES: usize = 1024;

#[derive(Clone, Copy)]
pub struct Instruction {
    op: u8,
    reg: u8,
    _padding: u16,
    offset: i32,
}

#[map]
static PC: Array<u64> = Array::with_max_entries(EHFRAME_ENTRIES);
#[map]
static RIP: Array<Instruction> = Array::with_max_entries(EHFRAME_ENTRIES);
#[map]
static RSP: Array<Instruction> = Array::with_max_entries(EHFRAME_ENTRIES);
#[map]
static RBP: Array<Instruction> = Array::with_max_entries(EHFRAME_ENTRIES);
#[map]
static RBX: Array<Instruction> = Array::with_max_entries(EHFRAME_ENTRIES);

#[map]
static USER_STACK: HashMap<[u64; MAX_STACK_DEPTH], u32> = HashMap::with_max_entries(1024);

#[entry("perf_event")]
fn profile(args: &bpf_perf_event_data) {
    // TODO find initial values
    let mut rip: usize = 0;
    let mut rsp: usize = 0;
    let mut rbp: usize = 0;
    let mut rbx: usize = 0;
    let mut stack = [0; MAX_STACK_DEPTH];
    for d in 0..MAX_STACK_DEPTH {
        stack[d] = rip as _;
        if rip == 0 {
            break;
        }
        // TODO binary search
        let mut i = 0;
        /*let mut i = EHFRAME_ENTRIES / 2;
        let mut inc = EHFRAME_ENTRIES / 2;
        while inc > 1 {
            inc = inc / 2;
            if PC[inc] > rip {
                inc
            }
        }*/
        // TODO exec instruction
        /*match RIP[i] {
        }
        match RSP[i] {
        }
        match RBP[i] {
        }
        match RBX[i] {
        }*/
    }
    let mut count = USER_STACK.get(&stack).unwrap_or_default();
    count += 1;
    USER_STACK.insert(&stack, &count);
}
