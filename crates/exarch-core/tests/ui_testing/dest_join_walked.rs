use exarch_core::types::DestDir;
use exarch_core::types::SafePath;
use exarch_core::types::Walked;
use std::path::PathBuf;

fn join_walked(dest: &DestDir, path: &SafePath<Walked>) -> PathBuf {
    dest.join(path)
}

fn main() {}
