#!/usr/bin/env bash
# 40.02 "Release artifacts": pack the release build (bench/release.sh output) for a release.
# Usage: bench/package.sh VERSION [OUTDIR]   (OUTDIR default: pkg/, gitignored)
# Output: OUTDIR/finalwisp-VERSION-x86_64-linux.tar.gz (one top directory: finalwisp, BUILDINFO, README.md,
#         LICENSE*/COPYING* if the repo has them) and OUTDIR/SHA256SUMS (the tarball, and the binary at its path inside
#         the tarball: `sha256sum -c SHA256SUMS` checks the download, and after `tar xf` the binary too).
# The tarball is reproducible for one build: sorted names, owner 0:0, mtime = the commit time, gzip -n. (BUILDINFO
# holds the build date, so two builds of one commit give two tarballs; the binary inside has the same md5.)
set -euo pipefail
ver=${1:?usage: bench/package.sh VERSION [OUTDIR]}
case "$ver" in
    */* | *' '* | .* | '') echo "package.sh: bad version '$ver' (no '/', spaces or leading '.')" >&2; exit 1 ;;
esac
here=$(dirname "$(readlink -f "${BASH_SOURCE[0]}")")
root=$(git -C "$here" rev-parse --show-toplevel)
outdir=$(readlink -m "${2:-$root/pkg}")
rel="$root/server/target/x86_64-unknown-linux-gnu/release"
for f in finalwisp BUILDINFO; do
    [ -f "$rel/$f" ] || { echo "package.sh: $rel/$f missing: run bench/release.sh first" >&2; exit 1; }
done
# the binary must be the one BUILDINFO describes, built from this checkout
md5=$(md5sum "$rel/finalwisp" | awk '{print $1}')
grep -qx "md5: $md5" "$rel/BUILDINFO" || { echo "package.sh: BUILDINFO md5 is not the binary's ($md5): rebuild" >&2; exit 1; }
grep -qx "git: $(git -C "$root" rev-parse HEAD)" "$rel/BUILDINFO" || { echo "package.sh: BUILDINFO is from another commit: rebuild" >&2; exit 1; }
grep -qx "dirty: no" "$rel/BUILDINFO" || { echo "package.sh: the build was dirty (BUILDINFO): commit first" >&2; exit 1; }

name="finalwisp-$ver-x86_64-linux"
stage=$(mktemp -d)
trap 'rm -rf -- "$stage"' EXIT
mkdir -m 0755 "$stage/$name" # (explicit: the umask must not change the tarball)
install -m 0755 "$rel/finalwisp" "$stage/$name/finalwisp"
install -m 0644 "$rel/BUILDINFO" "$root/README.md" "$stage/$name/"
for f in "$root"/LICENSE* "$root"/COPYING* "$root"/NOTICE; do
    [ -f "$f" ] && install -m 0644 "$f" "$stage/$name/"
done
mkdir -p "$outdir"
mtime=$(git -C "$root" log -1 --format=%ct)
tar -C "$stage" --sort=name --owner=0 --group=0 --numeric-owner --mtime="@$mtime" -cf - "$name" | gzip -n -9 > "$outdir/$name.tar.gz"
(cd "$stage" && sha256sum "$name/finalwisp") > "$stage/sums"
(cd "$outdir" && sha256sum "$name.tar.gz") >> "$stage/sums"
mv "$stage/sums" "$outdir/SHA256SUMS"
echo "package.sh: $outdir/$name.tar.gz (binary md5 $md5)"
cat "$outdir/SHA256SUMS"
