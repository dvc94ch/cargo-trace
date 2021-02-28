use anyhow::Result;
use bpf_utils::ehframe::{Instruction, Op, Reg};
use bpf_utils::elf::Elf;
use bpf_utils::maps::AddressMap;

pub struct UnwindMap {
    pc: Vec<u64>,
    rip: Vec<Instruction>,
    rsp: Vec<Instruction>,
}

impl UnwindMap {
    pub fn load() -> Result<Self> {
        let map = AddressMap::load_self()?;
        let mut pc = vec![];
        let mut rip = vec![];
        let mut rsp = vec![];
        for entry in map.iter() {
            let elf = Elf::open(&entry.path)?;
            let table = elf.unwind_table()?;
            for row in table.rows.iter() {
                let addr = entry.start_addr + row.start_address;
                pc.push(addr as u64);
                rip.push(row.rip.into());
                rsp.push(row.rsp.into());
            }
        }
        Ok(Self { pc, rip, rsp })
    }

    pub fn binary_search(&self, ip: u64) -> usize {
        let mut left = 0;
        let mut right = self.pc.len() - 1;
        let mut i = 0;
        for _ in 0..24 {
            if left > right {
                break;
            }
            i = (left + right) / 2;
            let pc = self.pc.get(i).copied().unwrap_or(u64::MAX);
            if pc < ip {
                left = i;
            } else {
                right = i;
            }
        }
        i
    }
}

pub struct UnwindContext {
    map: UnwindMap,
    rip: u64,
    rsp: u64,
}

impl UnwindContext {
    /// Get the unwind context of the point from which this function was called.
    ///
    /// This context must be used straight away: it is unsafe to alter the call stack
    /// before using it, in particular by returning from the calling function.
    pub unsafe fn get_context() -> Result<UnwindContext> {
        let map = UnwindMap::load()?;
        let mut ctx: libc::ucontext_t = std::mem::zeroed();
        if libc::getcontext(&mut ctx as *mut _) < 0 {
            panic!("couldn't getcontext");
        }
        Ok(Self {
            map,
            rip: ctx.uc_mcontext.gregs[libc::REG_RIP as usize] as u64,
            rsp: ctx.uc_mcontext.gregs[libc::REG_RSP as usize] as u64,
        })
    }

    /// Unwind the passed context once, in place.
    /// Returns `true` if the context was actually unwinded, or `false` if the end of
    /// the call stack was reached.
    pub unsafe fn unwind_context(&mut self) -> bool {
        if self.rip == 0 {
            return false;
        }

        let i = self.map.binary_search(self.rip);
        let irip = self.map.rip[i];
        let irsp = self.map.rsp[i];

        let cfa = execute_instruction(&irsp, self.rip, self.rsp, 0).unwrap();
        let rip = execute_instruction(&irip, self.rip, self.rsp, cfa).unwrap_or_default();

        self.rip = rip;
        self.rsp = cfa;

        true
    }

    pub fn rip(&self) -> u64 {
        self.rip
    }

    pub fn rsp(&self) -> u64 {
        self.rsp
    }
}

fn execute_instruction(ins: &Instruction, rip: u64, rsp: u64, cfa: u64) -> Option<u64> {
    match (ins.op(), ins.reg(), ins.offset()) {
        (Op::CfaOffset, None, Some(offset)) => {
            Some(unsafe { *((cfa as i64 + offset) as *const u64) })
        }
        (Op::Register, Some(Reg::Rip), Some(offset)) => Some((rip as i64 + offset) as u64),
        (Op::Register, Some(Reg::Rsp), Some(offset)) => Some((rsp as i64 + offset) as u64),
        _ => None,
    }
}

/// Call the passed function once per frame in the call stack, most recent frame first,
/// with the current context as its sole argument.
pub fn walk_stack(mut f: impl FnMut(&UnwindContext)) {
    let mut ctx = unsafe { UnwindContext::get_context().unwrap() };
    unsafe { ctx.unwind_context() };
    while unsafe { ctx.unwind_context() } {
        f(&ctx);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use core::ffi::c_void;

    #[test]
    fn test_init() {
        walk_stack(|ctx| {
            backtrace::resolve(ctx.rip as *const c_void as *mut _, |symbol| {
                println!("{:?}", symbol.name().unwrap());
            })
        })
    }
}
