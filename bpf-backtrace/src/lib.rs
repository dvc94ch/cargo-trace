use bpf_utils::ehframe::{Instruction, Op, Reg, UnwindTable, UnwindTableRow};
use bpf_utils::elf::Elf;
use findshlibs::{SharedLibrary, TargetSharedLibrary};
use std::path::PathBuf;

pub struct UnwindMap {
    entries: Vec<UnwindEntry>,
}

impl UnwindMap {
    pub fn load() -> Self {
        let mut entries = vec![];
        TargetSharedLibrary::each(|shlib| {
            let path = shlib.name().to_str().unwrap();
            if !path.contains("linux-vdso") {
                let load_addr = shlib.actual_load_addr().into();
                let len = shlib.len();
                let elf = Elf::open(shlib.name()).unwrap();
                let table = elf.unwind_table().unwrap();
                entries.push(UnwindEntry {
                    load_addr,
                    len,
                    path: shlib.name().into(),
                    table,
                });
            }
        });
        entries.sort_unstable_by_key(|entry| entry.load_addr);
        for entry in &entries {
            log::debug!(
                "0x{:x} 0x{:x} {}",
                entry.load_addr,
                entry.len,
                entry.path.display()
            );
        }
        Self { entries }
    }

    pub fn entry(&self, address: usize) -> Option<&UnwindEntry> {
        let i = match self
            .entries
            .binary_search_by_key(&address, |entry| entry.load_addr)
        {
            Ok(i) => i,
            Err(0) => 0,
            Err(i) => i - 1,
        };
        let entry = &self.entries[i];
        if address < entry.load_addr || address > entry.load_addr + entry.len {
            None
        } else {
            Some(entry)
        }
    }
}

pub struct UnwindEntry {
    load_addr: usize,
    len: usize,
    path: PathBuf,
    table: UnwindTable,
}

impl UnwindEntry {
    pub fn row(&self, address: usize) -> Option<&UnwindTableRow> {
        //println!("looking for 0x{:x}", address);
        /*let mut left = 0;
        let mut right = self.table.rows.len() - 1;
        let mut i = 0;
        for _ in 0..20 {
            if left > right {
                break;
            }
            i = (left + right) / 2;
            let pc = self.table.rows.get(i).map(|r| r.start_address).unwrap_or(usize::MAX);
            if pc < rip {
                left = i + 1;
            } else {
                right = i;
            }
        }*/
        let i = match self
            .table
            .rows
            .binary_search_by_key(&address, |entry| entry.start_address)
        {
            Ok(i) => i,
            Err(0) => 0,
            Err(i) => i - 1,
        };
        let row = &self.table.rows[i];
        if address < row.start_address || address >= row.end_address {
            //log::debug!("missing row for 0x{:x}", address);
            //log::debug!("closest match   0x{:x}", row.start_address);
            //log::debug!("                0x{:x}", row.end_address);
            None
        } else {
            Some(row)
        }
    }
}

#[derive(Clone, Copy, Debug, Default)]
#[repr(C)]
pub struct UnwindContext {
    load_addr: usize,
    rip: usize,
    rsp: usize,
    rbp: usize,
    rbx: usize,
}

impl UnwindContext {
    /// Get the unwind context of the point from which this function was called.
    ///
    /// This context must be used straight away: it is unsafe to alter the call stack
    /// before using it, in particular by returning from the calling function.
    pub unsafe fn get_context() -> UnwindContext {
        let mut ctx: libc::ucontext_t = std::mem::zeroed();
        if libc::getcontext(&mut ctx as *mut _) < 0 {
            panic!("couldn't getcontext");
        }
        UnwindContext {
            load_addr: 0,
            rip: ctx.uc_mcontext.gregs[libc::REG_RIP as usize] as usize,
            rsp: ctx.uc_mcontext.gregs[libc::REG_RSP as usize] as usize,
            rbp: ctx.uc_mcontext.gregs[libc::REG_RBP as usize] as usize,
            rbx: ctx.uc_mcontext.gregs[libc::REG_RBX as usize] as usize,
        }
    }

    /// Unwind the passed context once, in place.
    /// Returns `true` if the context was actually unwinded, or `false` if the end of
    /// the call stack was reached.
    pub unsafe fn unwind_context(&mut self, map: &mut UnwindMap) -> bool {
        if self.rip == 0 || self.rip + 1 == 0 {
            return false;
        }

        let entry = if let Some(entry) = map.entry(self.rip) {
            entry
        } else {
            return false;
        };
        let row = if let Some(row) = entry.row(self.rip - entry.load_addr) {
            row
        } else {
            return false;
        };

        if !row.rip.is_implemented() || !row.rsp.is_defined() {
            return false;
        }

        let rsp = execute_instruction(&row.rsp, self, 0).unwrap();
        let rip = execute_instruction(&row.rip, self, rsp).unwrap_or_default();
        let rbp = execute_instruction(&row.rbp, self, rsp).unwrap_or_default();
        let rbx = execute_instruction(&row.rbx, self, rsp).unwrap_or_default();

        self.rip = rip as usize;
        self.rsp = rsp as usize;
        self.rbp = rbp as usize;
        self.rbx = rbx as usize;

        true
    }

    pub fn load_addr(&self) -> usize {
        self.load_addr
    }

    pub fn rip(&self) -> usize {
        self.rip
    }

    pub fn rsp(&self) -> usize {
        self.rsp
    }

    pub fn rbp(&self) -> usize {
        self.rbp
    }

    pub fn rbx(&self) -> usize {
        self.rbx
    }
}

fn execute_instruction(ins: &Instruction, regs: &UnwindContext, next_rsp: u64) -> Option<u64> {
    match (ins.op(), ins.reg(), ins.offset()) {
        (Op::CfaOffset, None, Some(offset)) => {
            Some(unsafe { *((next_rsp as i64 + offset) as *const u64) })
        }
        (Op::Register, Some(Reg::Rip), Some(offset)) => Some((regs.rip as i64 + offset) as u64),
        (Op::Register, Some(Reg::Rsp), Some(offset)) => Some((regs.rsp as i64 + offset) as u64),
        (Op::Register, Some(Reg::Rbp), Some(offset)) => Some((regs.rbp as i64 + offset) as u64),
        (Op::Register, Some(Reg::Rbx), Some(offset)) => Some((regs.rbx as i64 + offset) as u64),
        _ => None,
    }
}

/// Call the passed function once per frame in the call stack, most recent frame first,
/// with the current context as its sole argument.
pub fn walk_stack(mut f: impl FnMut(&UnwindContext)) {
    let mut unwind_map = UnwindMap::load();
    let mut ctx = unsafe { UnwindContext::get_context() };
    unsafe { ctx.unwind_context(&mut unwind_map) };
    while unsafe { ctx.unwind_context(&mut unwind_map) } {
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
