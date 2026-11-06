use exarch_core::DestDir;
use exarch_core::SafePath;
use exarch_core::Walked;
use std::path::PathBuf;

fn join_walked(dest: &DestDir, path: &SafePath<Walked>) -> PathBuf {
    dest.join(path)
}

fn main() {}
