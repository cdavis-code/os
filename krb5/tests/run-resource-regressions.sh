#!/usr/bin/env bash
# Bounded local calls only; no socket or KDC needed for these regressions.
set -euo pipefail
source_dir=$(cd "${1:?source directory required}" && pwd)
build_dir=$(cd "${2:?build directory required}" && pwd)
cc=${CC:-cc}
"$cc" -DHAVE_CONFIG_H -O0 -fno-builtin -Wall -Wextra \
  -I"$build_dir/include" -I"$source_dir/src/include" \
  "$source_dir/tests/resource_regressions.c" -L"$build_dir/lib" \
  -Wl,-rpath,"$build_dir/lib" -lgssrpc -lkrb5 -ldl \
  -o "$build_dir/resource_regressions"
sha256sum "$build_dir/resource_regressions" "$build_dir/lib/libgssrpc.so" "$build_dir/lib/libkrb5.so"
ulimit -v 262144
result=0
for name in auth_default_rejection auth_cleanup asn1_single_allocation; do
  status=0
  LD_LIBRARY_PATH="$build_dir/lib" timeout 20s "$build_dir/resource_regressions" "$name" || status=$?
  case "$status" in
    0) printf '%s=PASS\n' "$name" ;;
    1) printf '%s=FAIL\n' "$name"; result=1 ;;
    *) printf '%s=SETUP_OR_RUNTIME_ERROR:%s\n' "$name" "$status"; exit 2 ;;
  esac
done
exit "$result"
