#!/bin/sh
# Assert the offensive toolchain baked into the runtime image is present and matches the
# versions this repository pins. Run after a build, or in CI against the built image:
#
#   make image-tools-check
#   scripts/verify-image-tools.sh artex:local
#
# Env: ARTEX_IMAGE (image to check), NUCLEI_VERSION (when set, the binary must report it).
set -eu

img="${1:-${ARTEX_IMAGE:-artex:local}}"
printf 'verifying toolchain in %s\n' "$img"

# Every path the wrappers depend on, plus a non-empty template set.
docker run --rm --entrypoint /bin/sh "$img" -c '
  set -eu
  for p in /usr/local/bin/nuclei /usr/local/bin/nuclei.real /opt/nuclei-templates \
           /opt/sqlmap/sqlmap.py /opt/commix/commix.py; do
    [ -e "$p" ] || { echo "missing: $p" >&2; exit 1; }
  done
  [ -n "$(ls -A /opt/nuclei-templates)" ] || { echo "empty: /opt/nuclei-templates" >&2; exit 1; }
  printf "paths ok\n"
'

# Each wrapper must actually run and report a version: the first output line is printed, the full
# output is shown only on failure. Command substitution is what makes the exit status visible - a
# tool piped straight into head reports head's status and a wrapper pointing at a missing file
# would pass silently, which is exactly how a broken wrapper survived the first build.
docker run --rm --entrypoint /bin/sh "$img" -c '
  set -eu
  for c in nuclei sqlmap commix; do
    flag="--version"
    if [ "$c" = nuclei ]; then flag="-version"; fi
    out=$("$c" "$flag" 2>&1) || { printf "%s failed:\n%s\n" "$c" "$out" >&2; exit 1; }
    printf "%-8s %s\n" "$c" "$(printf "%s\n" "$out" | head -1)"
  done
'

if [ -n "${NUCLEI_VERSION:-}" ]; then
  if ! docker run --rm --entrypoint /bin/sh "$img" -c "nuclei -version 2>&1 | grep -q '${NUCLEI_VERSION}'"; then
    echo "nuclei version mismatch: expected ${NUCLEI_VERSION}" >&2
    exit 1
  fi
fi

printf 'toolchain ok\n'
