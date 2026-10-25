//! Helpers shared by the integration tests.

#![allow(dead_code, clippy::expect_used)]

/// Flips the low bit of the first byte of `marker` found in `bytes`, so stored
/// data fails its checksum.
pub fn flip_first(bytes: &mut [u8], marker: &[u8]) {
    let at = bytes
        .windows(marker.len())
        .position(|w| w == marker)
        .expect("marker present");
    bytes[at] ^= 0x01;
}
