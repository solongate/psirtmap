#!/bin/sh
set -eu

repository="solongate/psirtmap"
install_dir="${PSIRTMAP_INSTALL_DIR:-}"
version="${PSIRTMAP_VERSION:-}"

need_command() {
  if ! command -v "$1" >/dev/null 2>&1; then
    printf 'Error: %s is required.\n' "$1" >&2
    exit 1
  fi
}

need_command curl
need_command tar

if [ -z "$install_dir" ]; then
  if command -v brew >/dev/null 2>&1 && [ -w "$(brew --prefix)/bin" ]; then
    install_dir="$(brew --prefix)/bin"
  elif [ -d /usr/local/bin ] && [ -w /usr/local/bin ]; then
    install_dir="/usr/local/bin"
  else
    install_dir="$HOME/.local/bin"
  fi
fi

if [ -z "$version" ]; then
  version=$(curl -fsSL "https://api.github.com/repos/$repository/releases/latest" |
    sed -n 's/.*"tag_name":[[:space:]]*"\([^"]*\)".*/\1/p' | head -n 1)
fi
if [ -z "$version" ]; then
  printf 'Error: could not determine the latest PSIRTMap release.\n' >&2
  exit 1
fi
case "$version" in
  v*) ;;
  *) version="v$version" ;;
esac

case "$(uname -s)" in
  Darwin) platform="darwin" ;;
  Linux) platform="linux" ;;
  *)
    printf 'Error: this installer supports macOS and Linux.\n' >&2
    exit 1
    ;;
esac

case "$(uname -m)" in
  arm64|aarch64) architecture="arm64" ;;
  x86_64|amd64) architecture="amd64" ;;
  *)
    printf 'Error: unsupported architecture %s.\n' "$(uname -m)" >&2
    exit 1
    ;;
esac

release_version=${version#v}
package="psirtmap_${release_version}_${platform}_${architecture}"
archive="$package.tar.gz"
base_url="https://github.com/$repository/releases/download/$version"
temporary_dir=$(mktemp -d "${TMPDIR:-/tmp}/psirtmap-install.XXXXXX")
trap 'rm -rf "$temporary_dir"' EXIT HUP INT TERM

printf 'Downloading PSIRTMap %s for %s/%s...\n' "$version" "$platform" "$architecture"
curl -fsSL "$base_url/$archive" -o "$temporary_dir/$archive"
curl -fsSL "$base_url/checksums.txt" -o "$temporary_dir/checksums.txt"

expected=$(awk -v name="$archive" '{ file=$2; sub(/^\.\//, "", file); if (file == name) { print $1; exit } }' "$temporary_dir/checksums.txt")
if [ -z "$expected" ]; then
  printf 'Error: release checksum for %s was not found.\n' "$archive" >&2
  exit 1
fi
if command -v sha256sum >/dev/null 2>&1; then
  actual=$(sha256sum "$temporary_dir/$archive" | awk '{print $1}')
elif command -v shasum >/dev/null 2>&1; then
  actual=$(shasum -a 256 "$temporary_dir/$archive" | awk '{print $1}')
else
  printf 'Error: sha256sum or shasum is required.\n' >&2
  exit 1
fi
if [ "$expected" != "$actual" ]; then
  printf 'Error: checksum verification failed.\n' >&2
  exit 1
fi

tar -xzf "$temporary_dir/$archive" -C "$temporary_dir"
mkdir -p "$install_dir"
cp "$temporary_dir/$package/psirtmap" "$install_dir/psirtmap.new"
chmod 0755 "$install_dir/psirtmap.new"
mv "$install_dir/psirtmap.new" "$install_dir/psirtmap"

printf '\nInstalled PSIRTMap %s to %s/psirtmap\n' "$version" "$install_dir"
case ":$PATH:" in
  *":$install_dir:"*)
    printf 'Run: psirtmap\n'
    ;;
  *)
    printf '\nAdd this directory to PATH once, then restart your terminal:\n'
    printf '  export PATH="%s:$PATH"\n' "$install_dir"
    printf '\nAfter that, run: psirtmap\n'
    ;;
esac
