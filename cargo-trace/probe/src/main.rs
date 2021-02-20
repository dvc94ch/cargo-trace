#![no_std]
#![no_main]

use bpf_helpers::{entry, map, program, sys, Array, HashMap};

program!(0xFFFF_FFFE, b"GPL");

const MAX_STACK_DEPTH: usize = 4;
const MAX_BIN_SEARCH_DEPTH: usize = 16;
const EHFRAME_ENTRIES: usize = 0xffff;

#[derive(Clone, Copy)]
pub struct Instruction {
    op: u8,
    reg: u8,
    _padding: u16,
    offset: i32,
}

#[map]
static ARRAY_SIZE: Array<u32> = Array::with_max_entries(1);
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
fn perf_event(args: &bpf_perf_event_data) {
    increment_stack_counter(&args.regs);
}

#[entry("kprobe")]
fn kprobe(args: &pt_regs) {
    increment_stack_counter(args);
}

fn increment_stack_counter(regs: &sys::pt_regs) {
    let mut stack = [0; MAX_STACK_DEPTH];
    backtrace(regs, &mut stack);
    let mut count = USER_STACK.get(&stack).unwrap_or_default();
    count += 1;
    USER_STACK.insert(&stack, &count);
}

fn backtrace(regs: &sys::pt_regs, stack: &mut [u64; MAX_STACK_DEPTH]) {
    let mut regs = regs.clone();
    for d in 0..MAX_STACK_DEPTH {
        stack[d] = regs.rip;
        if regs.rip == 0 {
            break;
        }
        let i = binary_search(regs.rip);
        if let Some(ins) = RIP.get(i) {
            if let Some(res) = execute_instuction(&ins, &regs) {
                regs.rip = res;
            } else {
                break;
            }
        }
        if let Some(ins) = RSP.get(i) {
            if let Some(res) = execute_instuction(&ins, &regs) {
                regs.rsp = res;
            } else {
                break;
            }
        }
        if let Some(ins) = RBP.get(i) {
            if let Some(res) = execute_instuction(&ins, &regs) {
                regs.rbp = res;
            }
        }
        if let Some(ins) = RBX.get(i) {
            if let Some(res) = execute_instuction(&ins, &regs) {
                regs.rbx = res;
            }
        }
    }
}

fn binary_search(rip: u64) -> u32 {
    let mut left = 0;
    let mut right = ARRAY_SIZE.get(0).unwrap_or(1) - 1;
    let mut i = 0;
    for _ in 0..MAX_BIN_SEARCH_DEPTH {
        if left > right {
            break;
        }
        i = (left + right) / 2;
        let pc = PC.get(i).unwrap_or(u64::MAX);
        if pc < rip {
            left = i + 1;
        } else {
            right = i;
        }
    }
    i
}

fn execute_instuction(ins: &Instruction, regs: &sys::pt_regs) -> Option<u64> {
    match ins.op {
        2 => {
            let unsafe_ptr = (regs.rsp as i64 + ins.offset as i64) as *const core::ffi::c_void;
            let mut res: u64 = 0;
            if unsafe { sys::bpf_probe_read(&mut res as *mut _ as *mut _, 8, unsafe_ptr) } == 0 {
                Some(res)
            } else {
                None
            }
        }
        3 => match ins.reg {
            10 => Some((regs.rbp as i64 + ins.offset as i64) as u64),
            11 => Some((regs.rbx as i64 + ins.offset as i64) as u64),
            15 => Some((regs.rsp as i64 + ins.offset as i64) as u64),
            16 => Some((regs.rip as i64 + ins.offset as i64) as u64),
            _ => None,
        },
        _ => None,
    }
}
