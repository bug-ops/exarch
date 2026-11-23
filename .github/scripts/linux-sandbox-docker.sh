#!/bin/sh
# Runs the Linux sandbox integration tests (Landlock enforcement, sandboxed
# stage-and-discard, --sandbox with --atomic) in a Linux container, so a macOS
# host can exercise them. The same tests run in CI (ci.yml, test job).
#
# Usage: .github/scripts/linux-sandbox-docker.sh [--require]
#   --require  set EXARCH_REQUIRE_LANDLOCK=1, so a kernel without Landlock
#              fails the tests instead of skipping the enforcement cases.
#
# Without --require the run is only meaningful when the probe line says
# "landlock enforced": a skipped test passes, so read the probe result.
#
# After the root run, a umask matrix (0277 0177 0377 0477 0677) extracts a flat
# and a nested archive as uid 65534. Root bypasses mode bits, so only the
# non-root run exercises staging umask handling. Expected: the flat archive and
# the nested archive under 0477 extract; the nested archive under the other
# masks exits nonzero, mentions the umask and leaves no .exarch-* directory.
set -eu

require=0
case "$#:${1:-}" in
  0:) ;;
  1:--require) require=1 ;;
  *)
    echo "usage: $0 [--require]" >&2
    exit 2
    ;;
esac

repo=$(cd "$(dirname "$0")/../.." && pwd -P)
image=${EXARCH_SANDBOX_IMAGE:-rust:1.100}

docker run --rm \
  -v "$repo:/src:ro" \
  -v exarch-sandbox-target:/target \
  -v exarch-sandbox-cargo:/usr/local/cargo/registry \
  -e CARGO_TARGET_DIR=/target \
  -e CARGO_TERM_COLOR=never \
  -e EXARCH_REQUIRE="$require" \
  "$image" bash -euo pipefail -c '
    # Landlock denies access to files on Docker Desktop virtiofs bind mounts, so
    # build and test from a copy on the container filesystem (-m gives fresh
    # mtimes, otherwise cargo replays stale cached diagnostics).
    mkdir /work
    tar -C /src --exclude=./target --exclude=./.local --exclude=./.git -cf - . | tar -C /work -mxf -
    cd /work
    uname -r
    cat /sys/kernel/security/lsm 2>/dev/null || echo "securityfs lsm list unavailable"
    if [ "$EXARCH_REQUIRE" = 1 ]; then export EXARCH_REQUIRE_LANDLOCK=1; fi

    cargo build -p exarch-cli --all-features
    probe=$(mktemp -d)
    mkdir "$probe/in" && echo x > "$probe/in/a" && tar -C "$probe/in" -cf "$probe/m.tar" a
    if /target/debug/exarch extract --sandbox require "$probe/m.tar" "$probe/out" >/dev/null 2>&1; then
      echo "probe: landlock enforced"
    else
      echo "probe: landlock NOT enforced; enforcement cases below are skipped unless --require"
    fi

    cargo test -p exarch-cli --all-features \
      --test sandbox --test sandbox_stage --test sandbox_spool --test password -- --test-threads=1

    # Non-root umask matrix: owner-restricting umasks only bite for uid != 0.
    nonroot="setpriv --reuid=65534 --regid=65534 --clear-groups"
    m=$(mktemp -d)
    chmod 755 "$m"
    mkdir -p "$m/flat" "$m/nested/d/sub"
    echo flat > "$m/flat/f"
    echo deep > "$m/nested/d/sub/f"
    tar -C "$m/flat" -cf "$m/flat.tar" f
    tar -C "$m/nested" -cf "$m/nested.tar" d
    mkdir "$m/run"
    chmod 777 "$m/run"
    failed=0
    for mask in 0277 0177 0377 0477 0677; do
      for kind in flat nested; do
        parent="$m/run/$kind-$mask"
        mkdir "$parent"
        chmod 777 "$parent"
        out="$parent/out"
        if [ "$kind" = flat ]; then expect="$out/f"; else expect="$out/d/sub/f"; fi
        status=0
        $nonroot sh -c "umask $mask && exec /target/debug/exarch extract $m/$kind.tar $out" \
          >"$m/log" 2>&1 || status=$?
        if [ "$kind" = nested ] && [ "$mask" != 0477 ]; then
          # Owner-restricting umask on nested trees must be refused, name the umask, and leave no staging dir.
          if [ "$status" -ne 0 ] && grep -q umask "$m/log" && [ -z "$(ls -A "$parent")" ]; then
            result=ok
          else
            result=FAILED
          fi
        elif [ "$status" -eq 0 ] && [ -r "$expect" ]; then
          result=ok
        else
          result=FAILED
        fi
        echo "umask $mask $kind: $result"
        if [ "$result" = FAILED ]; then
          cat "$m/log"
          ls -A "$parent"
          failed=1
        fi
      done
    done
    exit "$failed"
  '
