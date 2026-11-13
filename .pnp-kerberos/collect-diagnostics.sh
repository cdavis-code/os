#!/usr/bin/env bash
# Copy only public diagnostic outputs; never traverse the APK cache or key dir.
set -euo pipefail
output=${1:?output directory required}
workspace=${2:-}
publish="$output/publish"
mkdir -p "$publish"
for name in runner.txt sdk-signature.json sdk-signature.log tool-sha256.txt sdk-apk-installed.txt melange-version.txt dependencies.log diagnostic-key.rsa.pub build.log scope.txt; do
  if [[ -f "$output/$name" && ! -L "$output/$name" ]]; then
    install -m 644 "$output/$name" "$publish/$name"
  fi
done
for name in sdk-keys packages; do
  if [[ -d "$output/$name" && ! -L "$output/$name" ]]; then
    while IFS= read -r -d '' file; do
      relative=${file#"$output/"}
      mkdir -p "$publish/$(dirname "$relative")"
      install -m 644 "$file" "$publish/$relative"
    done < <(find "$output/$name" -type f \( -name '*.pub' -o -name '*.apk' \) -print0)
  fi
done
if [[ -n "$workspace" && -d "$workspace" && ! -L "$workspace" ]]; then
  while IFS= read -r -d '' file; do
    relative=${file#"$workspace/"}
    mkdir -p "$publish/test-logs/$(dirname "$relative")"
    install -m 644 "$file" "$publish/test-logs/$relative"
  done < <(find "$workspace" -type f \( -name testlog -o -name krb5kdc.log -o -name kadmind5.log \) -print0)
fi
chmod -R a+rX "$publish"
