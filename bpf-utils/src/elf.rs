use addr2line::{gimli, object, Context, Location};
use anyhow::Result;
use memmap::Mmap;
use object::elf::FileHeader64;
use object::read::elf::{Dyn, ElfFile, ProgramHeader};
use object::{NativeEndian, Object, ObjectSymbol};
use std::fs::File;
use std::path::Path;
use thiserror::Error;

#[derive(Debug, Error)]
#[error("Offset `{1}` out of range of `{1}`")]
pub struct OffsetOutOfRange(String, usize);

pub struct Dwarf {
    _file: File,
    _mmap: Mmap,
    obj: ElfFile<'static, FileHeader64<NativeEndian>>,
    ctx: Context<gimli::EndianRcSlice<gimli::RunTimeEndian>>,
}

impl Dwarf {
    pub fn open_elf<T: AsRef<Path>>(path: T) -> Result<Self> {
        let file = File::open(path)?;
        let mmap = unsafe { Mmap::map(&file) }?;
        let data: &'static [u8] = unsafe { std::slice::from_raw_parts(mmap.as_ptr(), mmap.len()) };
        let obj = ElfFile::parse(data)?;
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

    pub fn build_id(&self) -> Result<Option<&[u8]>> {
        Ok(self.obj.build_id()?)
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

    pub fn dynamic(&self) -> Result<Vec<String>> {
        let mut libs = vec![];
        for segment in self.obj.raw_segments() {
            if let Some(entries) = segment.dynamic(NativeEndian, self.obj.data())? {
                let mut strtab = 0;
                let mut strsz = 0;
                let mut dt_needed = vec![];
                for entry in entries {
                    match entry.d_tag(NativeEndian) as u32 {
                        object::elf::DT_STRTAB => strtab = entry.d_val(NativeEndian),
                        object::elf::DT_STRSZ => strsz = entry.d_val(NativeEndian),
                        object::elf::DT_NEEDED => dt_needed.push(entry.d_val(NativeEndian)),
                        _ => {}
                    }
                }
                let mut dynstr = object::StringTable::default();
                for segment in self.obj.raw_segments() {
                    if let Ok(Some(data)) =
                        segment.data_range(NativeEndian, self.obj.data(), strtab, strsz)
                    {
                        dynstr = object::StringTable::new(data);
                        break;
                    }
                }
                for needed in dt_needed {
                    if let Ok(lib) = dynstr.get(needed as _) {
                        let lib = std::str::from_utf8(lib)?;
                        libs.push(lib.to_string());
                    }
                }
            }
        }
        Ok(libs)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const PATH: &str = "../target/debug/hello-world";

    #[test]
    fn test_elf() -> Result<()> {
        let path = Path::new(env!("CARGO_MANIFEST_DIR")).join(PATH);
        let dwarf = Dwarf::open_dwarf(&path)?;
        let address = dwarf.resolve_symbol("main", 0)?.unwrap();
        let symbol = dwarf.resolve_address(address)?.unwrap();
        assert_eq!(symbol, "main");
        println!("address of main: 0x{:x}", address);
        println!("build id: {:?}", dwarf.build_id()?.unwrap());
        println!("dynamic: {:?}", dwarf.dynamic()?);
        let location = dwarf.resolve_location(0x5340)?.unwrap();
        println!(
            "location: {:?}:{:?}:{:?}",
            location.file, location.line, location.column
        );
        assert_eq!(location.line.unwrap(), 1);
        Ok(())
    }
}
