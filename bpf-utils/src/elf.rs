use anyhow::Result;
use memmap::Mmap;
use object::{File as ElfFile, Object, ObjectSymbol};
use std::fs::File;
use std::path::Path;
use thiserror::Error;

#[derive(Debug, Error)]
#[error("Symbol `{0}` not found.")]
pub struct SymbolNotFound(String);

#[derive(Debug, Error)]
#[error("Offset `{1}` out of range of `{1}`")]
pub struct OffsetOutOfRange(String, usize);

pub fn resolve_symbol(path: &Path, symbol: &str, offset: usize) -> Result<usize> {
    let file = File::open(path)?;
    let file = unsafe { Mmap::map(&file) }?;
    let file = ElfFile::parse(&*file)?;
    for sym in file.symbols() {
        if sym.name() == Ok(symbol) {
            if offset < sym.size() as usize {
                return Ok(sym.address() as usize + offset);
            } else {
                return Err(OffsetOutOfRange(symbol.to_string(), offset).into());
            }
        }
    }
    Err(SymbolNotFound(symbol.to_string()).into())
}
