//! Defines the `acl_copy` cfg for the targets whose destination ACL is copied
//! onto an atomically published root: Linux, Android and macOS.
//!
//! Adding a platform means adding it to the one list below.

const ACL_COPY_TARGETS: &[&str] = &["linux", "android", "macos"];

fn main() {
    println!("cargo::rerun-if-changed=build.rs");
    println!("cargo::rustc-check-cfg=cfg(acl_copy)");
    let target_os = std::env::var("CARGO_CFG_TARGET_OS").unwrap_or_default();
    if ACL_COPY_TARGETS.contains(&target_os.as_str()) {
        println!("cargo::rustc-cfg=acl_copy");
    }
}
