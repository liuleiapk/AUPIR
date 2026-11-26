#!/usr/bin/env bash
set -euo pipefail

script_dir="$(cd "$(dirname "$0")" && pwd)"
vendor_dir="${TMPDIR:-/tmp}/two-server-dpf-cpp"
build_dir="$script_dir/build"
archive="$vendor_dir/dpf-cpp.tar.gz"
source_dir="$vendor_dir/src"
dpf_commit="14bafa285845d5c4e5ab28b030283258aad67e48"
expected_sha="06442f991920e1fba98d4a5ee35bda9daf8d650e5926f091b4188bae2f652439"

if [[ "${1:-}" == "--clean" ]]; then
  rm -rf "$vendor_dir" "$build_dir"
elif [[ "${1:-}" == "--clean-build-only" ]]; then
  rm -rf "$build_dir"
fi

mkdir -p "$vendor_dir" "$build_dir"
if [[ -f "$archive" ]] && [[ "$(sha256sum "$archive" | awk '{print $1}')" != "$expected_sha" ]]; then
  rm -f "$archive"
fi
if [[ ! -f "$archive" ]]; then
  curl -L --fail "https://api.github.com/repos/dkales/dpf-cpp/tarball/$dpf_commit" -o "$archive"
fi
actual_sha="$(sha256sum "$archive" | awk '{print $1}')"
if [[ "$actual_sha" != "$expected_sha" ]]; then
  echo "dpf-cpp archive SHA-256 mismatch: $actual_sha" >&2
  exit 1
fi
if [[ ! -f "$source_dir/.patched" ]]; then
  rm -rf "$source_dir"
  mkdir -p "$source_dir"
  tar -xzf "$archive" -C "$source_dir" --strip-components=1
  patch -d "$source_dir" -p1 < "$script_dir/dpf_cpp_secure_rng.patch"
  touch "$source_dir/.patched"
fi

g++ -O3 -DNDEBUG -std=c++17 -maes -msse2 -msse4.1 -mavx2 -mpclmul \
  -pthread -Wno-ignored-attributes -I"$source_dir" \
  "$script_dir/backend.cpp" \
  "$source_dir/AES.cpp" "$source_dir/Defines.cpp" "$source_dir/Log.cpp" \
  "$source_dir/PRNG.cpp" "$source_dir/dpf.cpp" \
  -lcrypto -o "$build_dir/backend"

"$build_dir/backend" selftest
