use anyhow::Result;
use std::collections::HashMap;
use std::fs::File;
use std::io::{BufRead, BufReader};
use std::path::{Path, PathBuf};

#[derive(Debug)]
pub struct AddressMap {
    map: Vec<AddressEntry>,
}

impl std::fmt::Display for AddressMap {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        for entry in &self.map {
            writeln!(f, "{}", entry)?;
        }
        Ok(())
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Hash)]
pub struct AddressEntry {
    pub path: PathBuf,
    pub start_addr: usize,
    pub end_addr: usize,
}

impl std::fmt::Display for AddressEntry {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        write!(
            f,
            "0x{:x}-0x{:x} {}",
            self.start_addr,
            self.end_addr,
            self.path.display()
        )
    }
}

impl AddressMap {
    pub fn load_pid(pid: u32) -> Result<Self> {
        Self::load(format!("/proc/{}/maps", pid))
    }

    pub fn load_self() -> Result<Self> {
        Self::load("/proc/self/maps")
    }

    fn load<T: AsRef<Path>>(path: T) -> Result<Self> {
        let file = BufReader::new(File::open(path)?);
        let mut entries = HashMap::<PathBuf, (usize, usize)>::new();
        for line in file.lines() {
            let line = line?;
            let mut columns = line.split(' ');
            let address = columns.next().unwrap();
            let path = columns.last().unwrap();
            if !Path::new(path).exists() {
                continue;
            }
            let mut address = address.split('-');
            let start = address.next().unwrap();
            let start = usize::from_str_radix(start, 16)?;
            let end = address.next().unwrap();
            let end = usize::from_str_radix(end, 16)?;
            let mut entry = entries.entry(path.into()).or_insert((start, end));
            entry.0 = usize::min(entry.0, start);
            entry.1 = usize::max(entry.1, end);
        }
        let mut map: Vec<AddressEntry> = entries
            .into_iter()
            .map(|(path, (start, end))| AddressEntry {
                path,
                start_addr: start,
                end_addr: end,
            })
            .collect();
        map.sort_unstable_by_key(|entry| entry.start_addr);
        Ok(Self { map })
    }

    pub fn iter(&self) -> impl Iterator<Item = &AddressEntry> {
        self.map.iter()
    }

    pub fn entry(&self, address: usize) -> Option<&AddressEntry> {
        let i = match self
            .map
            .binary_search_by_key(&address, |entry| entry.start_addr)
        {
            Ok(i) => i,
            Err(0) => 0,
            Err(i) => i - 1,
        };
        let entry = &self.map[i];
        if address < entry.start_addr || address > entry.end_addr {
            None
        } else {
            Some(entry)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_maps() {
        let maps = AddressMap::load_self().unwrap();
        println!("{}", maps);
    }
}
