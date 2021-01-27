use addr2line::{gimli, object, Context, Location};
use anyhow::Result;
use memmap::Mmap;
use object::{Object, ObjectSymbol};
use std::fs::File;
use std::path::Path;
use thiserror::Error;

#[derive(Debug, Error)]
#[error("Offset `{1}` out of range of `{1}`")]
pub struct OffsetOutOfRange(String, usize);

pub struct Dwarf {
    _file: File,
    _mmap: Mmap,
    obj: object::File<'static>,
    ctx: Context<gimli::EndianRcSlice<gimli::RunTimeEndian>>,
}

impl Dwarf {
    pub fn open_elf<T: AsRef<Path>>(path: T) -> Result<Self> {
        let file = File::open(path)?;
        let mmap = unsafe { Mmap::map(&file) }?;
        let data: &'static [u8] = unsafe { std::slice::from_raw_parts(mmap.as_ptr(), mmap.len()) };
        let obj = object::File::parse(data)?;
        let ctx = Context::new(&obj)?;
        Ok(Self {
            _file: file,
            _mmap: mmap,
            obj,
            ctx,
        })
    }

    pub fn open_dwarf<T: AsRef<Path>>(path: T) -> Result<Self> {
        let me = Self::open_elf(path.as_ref())?;
        if me.obj.has_debug_symbols() {
            return Ok(me);
        }
        let debug_path = moria::locate_debug_symbols(&me.obj, path.as_ref())?;
        Self::open_elf(&debug_path)
    }

    pub fn open_build_id(id: &[u8]) -> Result<Self> {
        let debug_path = moria::locate_debug_build_id(id)?;
        Self::open_elf(&debug_path)
    }

    pub fn resolve_symbol(&self, symbol: &str, offset: usize) -> Result<Option<usize>> {
        for sym in self.obj.symbols() {
            if sym.name() == Ok(symbol) {
                if offset < sym.size() as usize {
                    return Ok(Some(sym.address() as usize + offset));
                } else {
                    return Err(OffsetOutOfRange(symbol.to_string(), offset).into());
                }
            }
        }
        Ok(None)
    }

    // TODO do instruction pointers correspond to a symbol or a symbol + offset?
    // are symbols ordered by address?
    pub fn resolve_address(&self, address: usize) -> Result<Option<&str>> {
        for sym in self.obj.symbols() {
            if sym.address() == address as _ {
                return Ok(Some(sym.name()?));
            }
        }
        Ok(None)
    }

    pub fn resolve_location(&self, address: usize) -> Result<Option<Location<'_>>> {
        Ok(self.ctx.find_location(address as _)?)
    }
}
