// Adaptec from https://github.com/rust-windowning/android-ndk-rs/blob/master/ndk-build/src/dylibs.rs
use crate::elf::{BuildId, Dwarf, Elf};
use crate::maps::AddressMap;
use anyhow::Result;
use cargo_subcommand::{CrateType, Subcommand};
use ptracer::{ContinueMode, Ptracer};
use std::collections::HashMap;
use std::path::{Path, PathBuf};

pub struct BinaryInfo {
    path: PathBuf,
    build_id: BuildId,
    map: HashMap<BuildId, (Elf, Option<Dwarf>)>,
    ptracer: Ptracer,
    address_map: AddressMap,
}

impl BinaryInfo {
    pub fn from_cargo_subcommand(cmd: &Subcommand) -> Result<Self> {
        let search_paths = get_cargo_search_paths(
            cmd.target_dir(),
            cmd.target().unwrap_or(""),
            cmd.profile().as_ref(),
        )?;
        log::debug!("{:?}", cmd);
        let artifact = &cmd.artifacts()[0];
        let path = cmd
            .target_dir()
            .join(cmd.target().unwrap_or(""))
            .join(cmd.profile())
            .join(artifact.as_ref())
            .join(artifact.file_name(CrateType::Bin, cmd.target().unwrap_or("")));
        Self::new(&path, &search_paths, &[])
    }

    pub fn new(path: &Path, search_paths: &[PathBuf], args: &[String]) -> Result<Self> {
        log::debug!("loading {}", path.display());
        let path = std::fs::canonicalize(path)?;
        let mut map = HashMap::with_capacity(10);
        let mut todo = vec![path.clone()];
        let mut root_build_id = None;
        while let Some(path) = todo.pop() {
            let elf = Elf::open(&path)?;
            let build_id = elf.build_id()?;
            if root_build_id.is_none() {
                root_build_id = Some(build_id);
            }
            for lib in elf.dynamic()? {
                todo.push(find_library_path(search_paths, lib)?.unwrap());
            }
            let dwarf = elf.dwarf().ok();
            map.insert(build_id, (elf, dwarf));
        }
        let build_id = root_build_id.unwrap();
        let mut ptracer = Ptracer::spawn(&path, args)?;
        log::debug!("loaded program with pid {}", ptracer.pid());
        /*let address_map = AddressMap::load_pid(i32::from(ptracer.pid()) as u32)?;
        let offset = map.get(&build_id).unwrap().0.resolve_symbol("_start", 0)?.unwrap();
        let load_addr = address_map.iter().find(|entry| entry.path == path).unwrap().start_addr;
        ptracer.insert_breakpoint(load_addr + offset)?;
        ptracer.enable_breakpoint(load_addr + offset)?;
        ptracer.cont(ContinueMode::Default)?;
        ptracer.remove_breakpoint(load_addr + offset)?;*/
        let address_map = AddressMap::load_pid(i32::from(ptracer.pid()) as u32)?;
        log::debug!("address map is: \n{}", address_map);
        Ok(Self {
            path,
            build_id,
            map,
            ptracer,
            address_map,
        })
    }

    pub fn path(&self) -> &Path {
        &self.path
    }

    pub fn elf(&self) -> &Elf {
        &self.map.get(&self.build_id).unwrap().0
    }

    pub fn dwarf(&self) -> Option<&Dwarf> {
        self.map.get(&self.build_id).unwrap().1.as_ref()
    }

    pub fn ptracer(&self) -> &Ptracer {
        &self.ptracer
    }

    pub fn pid(&self) -> u32 {
        i32::from(self.ptracer.pid()) as _
    }

    pub fn cont_and_wait(&self) -> Result<()> {
        ptracer::nix::sys::ptrace::cont(self.ptracer.pid(), None)?;
        ptracer::nix::sys::wait::waitpid(self.ptracer.pid(), None)?;
        Ok(())
    }

    pub fn address_map(&self) -> &AddressMap {
        &self.address_map
    }

    pub fn print_frame(&self, i: usize, build_id: &BuildId, offset: usize) -> Result<()> {
        let (elf, dwarf) = self.map.get(&build_id).unwrap();
        if let Some(dwarf) = dwarf {
            let mut iter = dwarf.find_frames(offset)?;
            let mut first = true;
            while let Some(frame) = iter.next()? {
                if first {
                    print!("{:4}: ", i);
                    first = false;
                } else {
                    print!("      ");
                }
                if let Some(function) = frame.function {
                    println!("{}", function.demangle()?);
                } else {
                    println!("0x{:x}", offset);
                }
                if let Some(location) = frame.location {
                    if let (Some(file), Some(line)) = (location.file, location.line) {
                        print!("             at {}:{}", file, line);
                    }
                    if let Some(col) = location.column {
                        println!(":{}", col);
                    } else {
                        println!("");
                    }
                }
            }
            if !first {
                return Ok(());
            }
        }
        if let Some(symbol) = elf.resolve_address(offset)? {
            println!("{:4}: {}", i, symbol);
        } else {
            println!("{:4}: 0x{:x}", i, offset);
        }
        println!("             at {}", elf.path().display());
        Ok(())
    }
}

impl std::fmt::Display for BinaryInfo {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        for (build_id, (elf, dwarf)) in &self.map {
            if let Some(dwarf) = dwarf {
                writeln!(
                    f,
                    "{} {} {}",
                    build_id,
                    elf.path().display(),
                    dwarf.path().display()
                )?;
            } else {
                writeln!(f, "{} {}", build_id, elf.path().display())?;
            }
        }
        Ok(())
    }
}

fn get_system_search_paths() -> Vec<PathBuf> {
    vec![PathBuf::from("/usr/lib")]
}

fn get_cargo_search_paths(
    target_dir: &Path,
    target_triple: &str,
    target_profile: &Path,
) -> Result<Vec<PathBuf>> {
    let mut paths = get_system_search_paths();

    let deps_dir = target_dir
        .join(target_triple)
        .join(target_profile)
        .join("build");

    for dep_dir in deps_dir.read_dir()? {
        let output_file = dep_dir?.path().join("output");
        if output_file.is_file() {
            use std::{
                fs::File,
                io::{BufRead, BufReader},
            };
            for line in BufReader::new(File::open(output_file)?).lines() {
                let line = line?;
                if line.starts_with("cargo:rustc-link-search=") {
                    let mut pie = line.split('=');
                    let (kind, path) = match (pie.next(), pie.next(), pie.next()) {
                        (Some(_), Some(kind), Some(path)) => (kind, path),
                        (Some(_), Some(path), None) => ("all", path),
                        _ => unreachable!(),
                    };
                    match kind {
                        // FIXME: which kinds of search path we interested in
                        "dependency" | "native" | "all" => paths.push(path.into()),
                        _ => (),
                    };
                }
            }
        }
    }

    Ok(paths)
}

fn find_library_path<S: AsRef<Path>>(paths: &[PathBuf], library: S) -> Result<Option<PathBuf>> {
    for path in paths {
        let lib_path = path.join(&library);
        if lib_path.exists() {
            return Ok(Some(std::fs::canonicalize(lib_path)?));
        }
    }
    Ok(None)
}

#[cfg(test)]
mod tests {
    use super::*;

    const TARGET_DIR: &str = "../target";
    const BIN: &str = "../target/debug/examples/hello_world";

    #[test]
    fn test_binary_info() -> Result<()> {
        let target_dir = Path::new(env!("CARGO_MANIFEST_DIR")).join(TARGET_DIR);
        let bin = Path::new(env!("CARGO_MANIFEST_DIR")).join(BIN);
        let search_paths = get_cargo_search_paths(&target_dir, "", Path::new("debug"))?;
        println!("{:?}", search_paths);
        let info = BinaryInfo::new(&bin, &search_paths)?;
        println!("{}", info);
        Ok(())
    }

    #[test]
    fn test_subcommand_binary_info() -> Result<()> {
        let args = "cargo cmd -- --example hello_world";
        let cmd = Subcommand::new(args.split(' ').map(|s| s.to_string()), "cmd", |_, _| {
            Ok(false)
        })?;
        let info = BinaryInfo::from_cargo_subcommand(&cmd)?;
        println!("{}", info);
        Ok(())
    }
}
