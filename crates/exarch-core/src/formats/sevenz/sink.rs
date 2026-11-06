//! 7z extraction into an entry sink.
//!
//! The gates are the host's; see [`super::extract`]. Only the destination
//! differs: the pre-pass runs against an empty in-memory tree instead of the
//! disk, because nothing can occupy a sink before the first entry, and it adds
//! the name-length limits of the path model.

use std::path::Path;

use super::extract::FilePlan;
use super::extract::PrePass;
use super::extract::SevenZTarget;
use super::write::refuse_undecoded_target_in;
use crate::ArchiveError;
use crate::PathModel;
use crate::Result;
use crate::SecurityConfig;
use crate::SinkOptions;
use crate::security::fs_view::CollisionRecording;
use crate::security::fs_view::NodeBudget;
use crate::security::fs_view::VirtualRoot;
use crate::security::fs_view::VirtualTree;
use crate::security::validator::EntryPath;
use crate::security::validator::Gated;
use crate::security::validator::NodeKind;
use crate::security::validator::ValidatorCore;
use crate::sink::EntrySink;
use crate::sink::SinkTarget;
use crate::types::SafePath;

/// The sink's pre-pass: paths against an empty tree.
///
/// Name lengths are checked for the entries delivery would validate (the
/// pre-pass hands it no file with a disallowed extension). The length of the
/// path an entry lands at after earlier symlinks resolve stays a delivery-time
/// check, because 7z link targets are undecoded here.
struct SinkPrePass<'a> {
    core: ValidatorCore<'a>,
    root: &'a VirtualRoot,
    tree: &'a VirtualTree,
    model: PathModel,
    config: &'a SecurityConfig,
}

impl SinkPrePass<'_> {
    fn check_name_lengths(&self, path: &Path) -> Result<()> {
        self.model
            .check_name_lengths(path)
            .map_err(ArchiveError::Io)
    }
}

impl PrePass for SinkPrePass<'_> {
    fn validate_path(&mut self, path: &Path, kind: NodeKind) -> Result<Gated<EntryPath<SafePath>>> {
        let ctx = self.core.context::<VirtualTree>();
        self.core
            .route_entry_in(path, kind, self.root, self.tree, &ctx)
    }

    fn directory(&mut self, landing: &SafePath) -> Result<()> {
        self.check_name_lengths(landing.as_path())
    }

    fn symlink(&mut self, link: &SafePath, file: &sevenz_rust2::ArchiveEntry) -> Result<()> {
        self.check_name_lengths(link.as_path())?;
        refuse_undecoded_target_in(link, file, self.root, self.config, self.tree)
    }

    fn file(&mut self, safe_path: &SafePath) -> Result<FilePlan> {
        self.check_name_lengths(safe_path.as_path())?;
        Ok(FilePlan::Reserve)
    }

    fn reserve_symlink(&mut self, size: u64) -> Result<()> {
        self.core.reserve_symlink(size)
    }

    fn reserve_file(&mut self, size: u64) -> Result<()> {
        self.core.reserve_file(size).map(drop)
    }
}

impl<S: EntrySink> SevenZTarget for SinkTarget<'_, S> {
    fn with_pre_pass(
        &self,
        config: &SecurityConfig,
        _options: SinkOptions,
        run: &mut dyn FnMut(&mut dyn PrePass) -> Result<()>,
    ) -> Result<()> {
        let model = self.model();
        let root = VirtualRoot::new();
        let tree = VirtualTree::new(
            &root,
            model,
            NodeBudget::from_config(config),
            CollisionRecording::Discard,
        );
        let mut pre = SinkPrePass {
            core: ValidatorCore::new(config),
            root: &root,
            tree: &tree,
            model,
            config,
        };
        run(&mut pre)
    }
}
