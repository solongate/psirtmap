#!/bin/sh
set -eu

repository_root=$(CDPATH= cd -- "$(dirname "$0")/.." && pwd)
test_root=$(mktemp -d "${TMPDIR:-/tmp}/psirtmap-installer-test.XXXXXX")
trap 'rm -rf "$test_root"' EXIT HUP INT TERM

custom_dir="$test_root/custom-bin"
other_dir="$test_root/home/.local/bin"
mkdir -p "$custom_dir" "$other_dir"
: >"$custom_dir/psirtmap"
: >"$other_dir/psirtmap"

HOME="$test_root/home" PSIRTMAP_INSTALL_DIR="$custom_dir" \
  sh "$repository_root/scripts/install.sh" uninstall

if [ -e "$custom_dir/psirtmap" ]; then
  printf 'custom installation was not removed\n' >&2
  exit 1
fi
if [ ! -e "$other_dir/psirtmap" ]; then
  printf 'uninstall removed a binary outside PSIRTMAP_INSTALL_DIR\n' >&2
  exit 1
fi

if HOME="$test_root/home" PSIRTMAP_INSTALL_DIR="$test_root/missing" \
  sh "$repository_root/scripts/install.sh" uninstall >/dev/null 2>&1; then
  printf 'uninstall unexpectedly succeeded for a missing custom installation\n' >&2
  exit 1
fi
if [ ! -e "$other_dir/psirtmap" ]; then
  printf 'failed uninstall removed a binary outside PSIRTMAP_INSTALL_DIR\n' >&2
  exit 1
fi

printf 'installer uninstall tests passed\n'
