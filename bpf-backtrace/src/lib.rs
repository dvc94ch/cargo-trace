use anyhow::Result;
use findshlibs::{SharedLibrary, TargetSharedLibrary};
use libloading::{Library, Symbol};
use std::ffi::c_void;
use std::path::{Path, PathBuf};
use std::process::Command;

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
                println!("0x{:x} 0x{:x} {}", load_addr, len, path);
                let path = Path::new(shlib.name()).to_owned();
                let mut eh_elf = path.file_name().unwrap().to_str().unwrap().to_string();
                eh_elf.push_str(".eh_elf.so");
                entries.push(UnwindEntry {
                    load_addr,
                    len,
                    path,
                    eh_elf,
                    lib: None,
                });
            }
        });
        entries.sort_unstable_by_key(|entry| entry.load_addr);
        Self { entries }
    }

    pub fn entry(&mut self, address: usize) -> Option<&mut UnwindEntry> {
        let i = match self
            .entries
            .binary_search_by_key(&address, |entry| entry.load_addr)
        {
            Ok(i) => i,
            Err(i) => i - 1,
        };
        let entry = &mut self.entries[i];
        if address <= entry.load_addr || address > entry.load_addr + entry.len {
            None
        } else {
            Some(entry)
        }
    }

    pub fn compile(&self) -> Result<()> {
        for entry in &self.entries {
            entry.compile()?;
        }
        Ok(())
    }
}

pub struct UnwindEntry {
    load_addr: usize,
    len: usize,
    path: PathBuf,
    eh_elf: String,
    lib: Option<Library>,
}

type EhElf = unsafe extern "C" fn(UnwindContext, *mut UnwindContext, usize) -> c_void;

impl UnwindEntry {
    pub fn addr(&self, pc: usize) -> usize {
        pc - self.load_addr
    }

    pub fn eh_elf(&mut self) -> Result<Symbol<'_, EhElf>> {
        if self.lib.is_none() {
            self.lib = Some(unsafe { Library::new(format!("./{}", self.eh_elf))? });
        }
        Ok(unsafe { self.lib.as_ref().unwrap().get(b"_eh_elf")? })
    }

    pub fn compile(&self) -> Result<()> {
        let output = Command::new("ehframe-bpf-compiler")
            .arg(&self.path)
            .output()?;
        print!("{}", std::str::from_utf8(&output.stdout)?);
        eprint!("{}", std::str::from_utf8(&output.stderr)?);
        if !output.status.success() {
            panic!("failed to compile .eh_frame");
        }
        Ok(())
    }
}

#[derive(Clone, Copy, Debug, Default)]
#[repr(transparent)]
pub struct UnwindFlags(u8);

impl UnwindFlags {
    pub fn rip(&self) -> bool {
        self.0 & (1 << 0) != 0
    }

    pub fn rsp(&self) -> bool {
        self.0 & (1 << 1) != 0
    }

    pub fn rbp(&self) -> bool {
        self.0 & (1 << 2) != 0
    }

    pub fn rbx(&self) -> bool {
        self.0 & (1 << 3) != 0
    }

    pub fn error(&self) -> bool {
        self.0 & (1 << 7) != 0
    }
}

#[derive(Clone, Copy, Debug, Default)]
#[repr(C)]
pub struct UnwindContext {
    flags: UnwindFlags,
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
        let unwind = UnwindContext {
            flags: UnwindFlags(0),
            rip: ctx.uc_mcontext.gregs[libc::REG_RIP as usize] as usize,
            rsp: ctx.uc_mcontext.gregs[libc::REG_RSP as usize] as usize,
            rbp: ctx.uc_mcontext.gregs[libc::REG_RBP as usize] as usize,
            rbx: ctx.uc_mcontext.gregs[libc::REG_RBX as usize] as usize,
        };
        unwind
    }

    /// Unwind the passed context once, in place.
    /// Returns `true` if the context was actually unwinded, or `false` if the end of
    /// the call stack was reached.
    pub unsafe fn unwind_context(&mut self, map: &mut UnwindMap) -> Result<bool> {
        if self.rip == 0 || self.rip + 1 == 0 {
            //println!("bottom of stack");
            return Ok(false);
        }
        let entry = map.entry(self.rip).unwrap();
        let tr_pc = entry.addr(self.rip);
        let eh_elf = entry.eh_elf()?;

        let mut next_ctx = UnwindContext::default();
        eh_elf(*self, &mut next_ctx, tr_pc);
        if next_ctx.flags.error() {
            //println!("no entry");
            return Ok(false); // no entry
        }
        if self.rip == next_ctx.rip {
            //println!("infinite loop");
            return Ok(false); // infinite loop
        }
        self.rip = next_ctx.rip;
        self.rsp = next_ctx.rsp;
        self.rbp = next_ctx.rbp;
        self.rbx = next_ctx.rbx;

        Ok(true)
    }

    pub fn ip(&self) -> usize {
        self.rip
    }

    pub fn sp(&self) -> usize {
        self.rsp
    }

    pub fn fp(&self) -> usize {
        self.rbp
    }
}

/// Call the passed function once per frame in the call stack, most recent frame first,
/// with the current context as its sole argument.
pub fn walk_stack(mut f: impl FnMut(&UnwindContext)) -> Result<()> {
    let mut unwind_map = UnwindMap::load();
    unwind_map.compile()?;
    let mut ctx = unsafe { UnwindContext::get_context() };
    unsafe { ctx.unwind_context(&mut unwind_map) }?;
    while unsafe { ctx.unwind_context(&mut unwind_map) }? {
        f(&ctx);
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_init() {
        walk_stack(|ctx| {
            backtrace::resolve(ctx.rip as *const c_void as *mut _, |symbol| {
                println!("{:?}", symbol.name().unwrap());
            })
        })
        .unwrap();
    }
}
