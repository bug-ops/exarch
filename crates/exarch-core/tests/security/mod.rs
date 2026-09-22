//! CVE regression tests for security vulnerabilities.

mod cve_regression;
mod entry_validator_hardlink;
mod entry_validator_path_traversal;
mod entry_validator_symlink;
mod entry_validator_zip_bomb;
mod hardlink_quota_bypass;
mod partial_report_skip_and_fail;
mod safe_path_ghsa_wcmx;
mod sevenz_traversal;
mod symlink_target_validation;
mod tar_budget_parity;
mod tar_ghsa_2026;
mod tar_ghsa_83g3_two_hop_symlink;
mod tar_metadata_bomb;
mod zip_ghsa_5j8q;
