// Copied from https://github.com/rust-windowning/android-ndk-rs/blob/master/ndk-build/src/dylibs.rs
use anyhow::Result;
use std::path::{Path, PathBuf};

pub fn get_libs_search_paths(
    target_dir: &Path,
    target_triple: &str,
    target_profile: &Path,
) -> Result<Vec<PathBuf>> {
    let mut paths = Vec::new();

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

pub fn find_library_path<S: AsRef<Path>>(paths: &[&Path], library: S) -> Result<Option<PathBuf>> {
    for path in paths {
        let lib_path = path.join(&library);
        if lib_path.exists() {
            return Ok(Some(std::fs::canonicalize(lib_path)?));
        }
    }
    Ok(None)
}
