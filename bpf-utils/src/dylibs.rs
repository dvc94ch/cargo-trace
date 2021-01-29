// Adaptec from https://github.com/rust-windowning/android-ndk-rs/blob/master/ndk-build/src/dylibs.rs
use crate::elf::{BuildId, Dwarf, Elf};
use anyhow::Result;
use cargo_subcommand::{CrateType, Subcommand};
use nix::sys::ptrace;
use nix::sys::wait::waitpid;
use spawn_ptrace::CommandPtraceSpawn;
use std::collections::HashMap;
use std::ffi::OsStr;
use std::path::{Path, PathBuf};
use std::process::Command;

pub struct BinaryInfo {
    path: PathBuf,
    map: HashMap<BuildId, (Elf, Option<Dwarf>)>,
}

impl BinaryInfo {
    pub fn from_cargo_subcommand(cmd: &Subcommand) -> Result<Self> {
        let search_paths = get_cargo_search_paths(
            cmd.target_dir(),
            cmd.target().unwrap_or(""),
            cmd.profile().as_ref(),
        )?;
        let artifact = &cmd.artifacts()[0];
        let path = cmd
            .target_dir()
            .join(cmd.target().unwrap_or(""))
            .join(cmd.profile())
            .join(artifact.as_ref())
            .join(artifact.file_name(CrateType::Bin, cmd.target().unwrap_or("")));
        Self::new(&path, &search_paths)
    }

    pub fn new(path: &Path, search_paths: &[PathBuf]) -> Result<Self> {
        let path = std::fs::canonicalize(path)?;
        let mut map = HashMap::with_capacity(10);
        let mut todo = vec![path.clone()];
        while let Some(path) = todo.pop() {
            let elf = Elf::open(&path)?;
            let build_id = elf.build_id()?;
            for lib in elf.dynamic()? {
                todo.push(find_library_path(search_paths, lib)?.unwrap());
            }
            let dwarf = elf.dwarf().ok();
            map.insert(build_id, (elf, dwarf));
        }
        Ok(Self { path, map })
    }

    pub fn spawn(&self) -> Result<Pid> {
        self.spawn_with_args::<_, &str>(std::iter::empty())
    }

    pub fn spawn_with_args<I, S>(&self, args: I) -> Result<Pid>
    where
        I: IntoIterator<Item = S>,
        S: AsRef<OsStr>,
    {
        let child = Command::new(&self.path).args(args).spawn_ptrace()?;
        Ok(Pid(child.id()))
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

fn get_system_search_paths() -> Result<Vec<PathBuf>> {
    Ok(vec![PathBuf::from("/usr/lib")])
}

fn get_cargo_search_paths(
    target_dir: &Path,
    target_triple: &str,
    target_profile: &Path,
) -> Result<Vec<PathBuf>> {
    let mut paths = get_system_search_paths()?;

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
                    let mut pie = line.split("=");
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

#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct Pid(u32);

impl Pid {
    pub fn cont_and_wait(&self) -> Result<()> {
        use nix::unistd::Pid;
        let pid = Pid::from_raw(self.0 as _);
        ptrace::cont(pid, None)?;
        waitpid(pid, None)?;
        Ok(())
    }
}

impl From<Pid> for u32 {
    fn from(pid: Pid) -> Self {
        pid.0
    }
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
