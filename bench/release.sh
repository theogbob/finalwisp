#!/usr/bin/env bash
# 60.09 R1 / 70.12 release build: static glibc (crt-static) finalwisp binary + BUILDINFO next to it.
# Usage: bench/release.sh            (from anywhere inside the repo; the allocator is the own pool, 70.25, always)
#        FEATURES="a b" bench/release.sh   (extra cargo features; none exist for a release today)
#        The built features are recorded in BUILDINFO ("features: none" normally) beside "allocator: pool".
#        NOFEAT=1 (the old glibc + 70.11 block cache build) was removed with that path (60.18 #11): it is refused.
# Output: server/target/x86_64-unknown-linux-gnu/release/{finalwisp,BUILDINFO}
# Fails if the build host's glibc is older than 2.34: below that the files/dns NSS modules are not built into
# libc and are dlopened from the host at runtime, which nss_builtin_only (main.rs) cannot prevent (70.12).
set -euo pipefail

MIN_GLIBC=2.34
TARGET=x86_64-unknown-linux-gnu
here=$(dirname "$(readlink -f "${BASH_SOURCE[0]}")")
root=$(git -C "$here" rev-parse --show-toplevel)
cd "$root/server"

glibc=$(getconf GNU_LIBC_VERSION 2>/dev/null | awk '{print $2}') || true
if [ -z "$glibc" ]; then
    echo "release.sh: cannot read the build host's glibc version (getconf GNU_LIBC_VERSION); need glibc >= $MIN_GLIBC" >&2
    exit 1
fi
if [ "$(printf '%s\n%s\n' "$MIN_GLIBC" "$glibc" | sort -V | head -n1)" != "$MIN_GLIBC" ]; then
    echo "release.sh: build host glibc $glibc < $MIN_GLIBC: files/dns NSS would be dlopened from the host at runtime (70.12); build on a newer host" >&2
    exit 1
fi

# the explicit --target keeps build scripts and proc macros dynamic (70.12)
# the target dir is fixed: BUILDINFO describes the binary at $out, not one a user CARGO_TARGET_DIR built elsewhere
export CARGO_TARGET_DIR="$root/server/target"
unset CARGO_BUILD_BUILD_DIR # intermediate files under the target dir too, so the path remap below covers them
# 40.02 reproducible release: the binary must not depend on WHERE it is built (repo path, $HOME, cache dirs), only on the
# source, the toolchain (rust-toolchain.toml) and the build image's gcc/binutils/glibc (recorded in BUILDINFO). A laptop build
# and the Forgejo clean-lane build of the same commit then have the same md5. RUSTFLAGS from the environment or a cargo config
# are ignored on purpose (deliberate: no host-specific codegen such as target-cpu=native in a release).
cargo_home=$(readlink -f "${CARGO_HOME:-$HOME/.cargo}")
sysroot=$(rustc --print sysroot)
remap="--remap-path-prefix=$cargo_home=/cargo --remap-path-prefix=$sysroot=/rust --remap-path-prefix=$root=/finalwisp"
export CFLAGS_x86_64_unknown_linux_gnu="-ffile-prefix-map=$cargo_home=/cargo -ffile-prefix-map=$root=/finalwisp"
if [ -n "${NOFEAT:-}" ] && [ "${NOFEAT}" != 0 ]; then
    echo "release.sh: NOFEAT=1 is gone: the old allocator path (glibc + the 70.11 block cache) was removed after base-4 (60.18 #11); build base-4 for it" >&2
    exit 1
fi
# FEATURES: cargo's list syntax (spaces or commas, optionally finalwisp/<name>), normalized to one space-separated list
extra=
# (review: every whitespace byte cargo splits on, CR/tab/newline too, becomes a separator before the check)
fs=$(printf '%s' "${FEATURES:-}" | tr ',\t\r\n\f\v' '      ')
for f in $fs; do
    f=${f#finalwisp/}
    case "$f" in
        "") ;;
        pooltest) echo "release.sh: pooltest is test-only, never in a release" >&2; exit 1 ;;
        own-alloc) echo "release.sh: own-alloc is no longer a feature: the pool is always built in (60.18 #11); drop it" >&2; exit 1 ;;
        *) extra="$extra $f" ;;
    esac
done
extra=${extra# }
features=$extra
RUSTFLAGS="-C target-feature=+crt-static $remap" cargo build --release --locked --target "$TARGET" ${extra:+--features "$extra"}

out="$root/server/target/$TARGET/release"
bin="$out/finalwisp"
command -v file >/dev/null || { echo "release.sh: file(1) is needed to check the binary is static" >&2; exit 1; }
if ! file -b "$bin" | grep -q 'static'; then
    echo "release.sh: $bin is not statically linked: $(file -b "$bin")" >&2
    exit 1
fi

hash=$(git rev-parse HEAD)
# 60.60 the release version: its one source is server/Cargo.toml (the binary reads the same line at compile time, so
# `finalwisp --version` says it and the build stays reproducible: the version is part of the source)
version=$(sed -n 's/^version = "\([^"]*\)".*/\1/p' "$root/server/Cargo.toml" | head -n1)
[ -n "$version" ] || { echo "release.sh: no version in server/Cargo.toml" >&2; exit 1; }
shown=$("$bin" --version)
if [ "$shown" != "finalwisp $version" ]; then
    echo "release.sh: the binary says '$shown', server/Cargo.toml says $version" >&2
    exit 1
fi
dirty=no
# dirty = any change in server/ or in the preset file it embeds (the build inputs), tracked or untracked (target/ is ignored)
status=$(git status --porcelain -- . ../contrib/public.conf)
if [ -n "$status" ]; then
    dirty=yes
fi
md5=$(md5sum "$bin" | awk '{print $1}')
rustc_v=$(rustc -V)
now=$(date -u +%Y-%m-%dT%H:%M:%SZ)
{
    echo "version: $version"
    echo "git: $hash"
    echo "dirty: $dirty"
    echo "rustc: $rustc_v"
    echo "glibc: $glibc (link version; runtime needs no glibc, hosts lookups via built-in files dns)"
    echo "cc: $(cc --version | head -n1)"
    echo "ld: $(ld --version | head -n1)"
    echo "target: $TARGET +crt-static"
    echo "features: ${features:-none}"
    echo "allocator: pool (70.25; the only path since 60.18 #11)"
    echo "date: $now"
    echo "md5: $md5"
} > "$out/BUILDINFO"
echo "release.sh: $bin"
cat "$out/BUILDINFO"
