#!/usr/bin/env bash
# Diagnostic package builds only. This entry point grants no release authority.
set -euo pipefail
root=$(git rev-parse --show-toplevel)
arch= recipe= output= inputs_lock= discovery=false
while (($#)); do
  case "$1" in
    --arch) arch=${2:?}; shift 2 ;;
    --recipe) recipe=${2:?}; shift 2 ;;
    --output) output=${2:?}; shift 2 ;;
    --inputs-lock) inputs_lock=${2:?}; shift 2 ;;
    --discover-inputs) discovery=true; shift ;;
    *) echo "REFUSED: unsupported build argument" >&2; exit 1 ;;
  esac
done
test "$recipe" = krb5.yaml || { echo 'REFUSED: only the reviewed krb5 recipe is supported' >&2; exit 1; }
test "$output" = ".pnp-kerberos/out/$arch" || { echo 'REFUSED: unexpected output directory' >&2; exit 1; }
gate_args=("$inputs_lock" "$arch")
if $discovery; then gate_args+=(--discovery); fi
gate=$(python3 "$root/.pnp-kerberos/source_lock.py" "${gate_args[@]}")
printf '%s\n' "$gate"
sdk=$(python3 -c 'import json,sys; print(json.loads(sys.argv[1])["sdk"])' "$gate")
test "$(uname -m)" = "$arch" || { echo 'REFUSED: this build requires a native Linux architecture' >&2; exit 1; }
test "$(uname -s)" = Linux || { echo 'REFUSED: use an isolated Linux runner' >&2; exit 1; }
mkdir -p "$output"
"${COSIGN:-cosign}" verify \
  --certificate-oidc-issuer=https://token.actions.githubusercontent.com \
  --certificate-identity=https://github.com/wolfi-dev/tools/.github/workflows/.build.yaml@refs/heads/main \
  "$sdk" > "$output/sdk-signature.json" 2> "$output/sdk-signature.log"
docker pull "$sdk"
container="kerberos-build-$arch"
trap 'docker rm -f "$container" >/dev/null 2>&1 || true' EXIT
sdk_mode=discovery
if ! $discovery; then
  echo 'REFUSED: captured-input replay must be implemented before acceptance' >&2
  exit 1
fi
timeout 110m docker run --name "$container" --hostname localhost --privileged --cpus=2 --memory=8g --pids-limit=2048 \
  --mount "type=bind,source=$root,target=/work" --workdir /work \
  --env HOST_UID="$(id -u)" --env HOST_GID="$(id -g)" \
  --env APK_ARCH="$arch" --env OUTPUT_DIR="$output" --env BUILD_MODE="$sdk_mode" \
  --entrypoint /bin/bash "$sdk" -euo pipefail -c '
    test "$(uname -m)" = "$APK_ARCH"
    test ! -S /var/run/docker.sock
    test -z "${HTTP_AUTH:-}"
    git config --global --add safe.directory /work
    bwrap --unshare-user --bind / / true
    mkdir -p "/work/$OUTPUT_DIR/sdk-keys" /tmp/kerberos-build-keys
    collect_on_exit() {
      status=$?
      rm -f /tmp/kerberos-build-keys/*
      ( bash /work/.pnp-kerberos/collect-diagnostics.sh "/work/$OUTPUT_DIR" /tmp/kerberos-workspace &&
        chown -R "$HOST_UID:$HOST_GID" "/work/$OUTPUT_DIR/publish" ) || {
        echo "ERROR: failed to retain diagnostic outputs" >&2
        test "$status" -ne 0 || status=1
      }
      exit "$status"
    }
    trap collect_on_exit EXIT
    printf "SDK hostname: %s\n" "$(hostname)"
    cp /lib/apk/db/installed "/work/$OUTPUT_DIR/sdk-apk-installed.txt"
    cp /etc/apk/keys/* "/work/$OUTPUT_DIR/sdk-keys/"
    sha256sum "$(command -v melange)" "$(command -v bwrap)" > "/work/$OUTPUT_DIR/tool-sha256.txt"
    melange version > "/work/$OUTPUT_DIR/melange-version.txt"
    melange keygen /tmp/kerberos-build-keys/local.rsa
    cp /tmp/kerberos-build-keys/local.rsa.pub "/work/$OUTPUT_DIR/diagnostic-key.rsa.pub"
    make MELANGE_RUNNER=bubblewrap ARCH="$APK_ARCH" KEY=/tmp/kerberos-build-keys/local.rsa \
      MELANGE_TMPDIR="/work/$OUTPUT_DIR/cache" \
      MELANGE_EXTRA_OPTS="--cleanup=false --workspace-dir=/tmp/kerberos-workspace --source-package --dependency-log=/work/$OUTPUT_DIR/dependencies.log --create-build-log --persist-lint-results" \
      package/krb5
    make MELANGE_RUNNER=bubblewrap ARCH="$APK_ARCH" KEY=/tmp/kerberos-build-keys/local.rsa \
      MELANGE_TMPDIR="/work/$OUTPUT_DIR/cache" test/krb5
    cp -R "packages/$APK_ARCH" "/work/$OUTPUT_DIR/packages"
    printf "diagnostic discovery build; ineligible for trusted publication\n" > "/work/$OUTPUT_DIR/scope.txt"
  ' 2>&1 | tee "$output/build.log"
