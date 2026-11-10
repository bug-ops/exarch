#!/bin/sh
# Runs inside a NetBSD or illumos VM: builds the exarch-core lib test binary as
# root, then runs the directory-mode and atomic-swap backup tests as an
# unprivileged user, because root ignores a directory's mode.
set -eu

. "$HOME/.cargo/env"

EXPECTED=5

built=$(cargo test -p exarch-core --lib --all-features --no-run 2>&1 | tee /dev/stderr)
bin=$(printf '%s\n' "$built" | sed -n 's/.*Executable unittests src\/lib.rs (\(.*\))/\1/p')
test -n "$bin"
bin=$(realpath "$bin")

path=$bin
while [ "$path" != / ]; do
  chmod a+rx "$path"
  path=$(dirname "$path")
done

scratch=/var/tmp/exarch-unprivileged
mkdir -p "$scratch"
chmod 1777 "$scratch"

runner=exarch-vm
id "$runner" >/dev/null 2>&1 || useradd -s /bin/sh "$runner"

su "$runner" -c "TMPDIR=$scratch $bin --exact formats::pinned_dir::tests::a_directory_without_read_access_is_opened_search_only formats::pinned_dir::tests::set_dir_mode_reaches_a_directory_whatever_access_its_mode_grants staging::tests::a_backup_that_cannot_be_removed_is_reported_as_a_warning staging::tests::a_read_only_destination_is_replaced_and_its_backup_removed staging::tests::a_destination_whatever_its_mode_is_replaced_and_its_backup_removed --nocapture > $scratch/output 2>&1" || { cat "$scratch/output"; exit 1; }
cat "$scratch/output"
grep -q "$EXPECTED passed" "$scratch/output"
