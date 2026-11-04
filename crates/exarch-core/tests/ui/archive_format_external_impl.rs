//! `ArchiveFormat` is sealed: a type outside the crate cannot implement it,
//! because the `Sealed` supertrait lives in a private module.

use std::path::Path;

use exarch_core::ExtractionOptions;
use exarch_core::ExtractionReport;
use exarch_core::ProgressCallback;
use exarch_core::Result;
use exarch_core::VerificationOptions;
use exarch_core::ArchiveManifest;
use exarch_core::VerificationReport;
use exarch_core::formats::traits::ArchiveFormat;

struct Mine;

impl ArchiveFormat for Mine {
    fn extract(
        self,
        _output_dir: &Path,
        _options: &ExtractionOptions,
        _progress: &mut dyn ProgressCallback,
    ) -> Result<ExtractionReport> {
        unreachable!()
    }

    fn list(self) -> Result<ArchiveManifest> {
        unreachable!()
    }

    fn verify(self, _options: &VerificationOptions) -> Result<VerificationReport> {
        unreachable!()
    }
}

fn main() {}
