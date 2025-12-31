//! Example: Creating archives with exarch-core
//!
//! Run with: `cargo run --example create_archive`

use exarch_core::ArchiveCreator;
use exarch_core::CreationConfig;
use exarch_core::create_archive;

fn main() -> Result<(), Box<dyn std::error::Error>> {
    // Example 1: Simple creation with default config
    println!("Example 1: Simple creation");
    let config = CreationConfig::default();

    // Create a test file for the example
    std::fs::write("example_file.txt", "Hello, exarch!")?;

    let report = create_archive("example.tar.gz", &["example_file.txt"], &config)?;
    println!("  Created archive with {} files", report.files_added);
    println!(
        "  Compression ratio: {:.1}%",
        report.compression_percentage()
    );

    // Cleanup
    std::fs::remove_file("example.tar.gz")?;

    // Example 2: Builder pattern with options
    println!("\nExample 2: Builder pattern");
    let report = ArchiveCreator::new()
        .output("example.zip")
        .add_source("example_file.txt")
        .compression_level(9)
        .create()?;
    println!("  Created ZIP with {} files", report.files_added);

    // Cleanup
    std::fs::remove_file("example.zip")?;
    std::fs::remove_file("example_file.txt")?;

    println!("\nExamples completed successfully!");
    Ok(())
}
