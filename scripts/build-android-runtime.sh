#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd -P)"
BUILD_ROOT="${ROOT}/.runtime-build"
WEBLIBRE_COMMIT="8e802b6cb4804e41d081ec42b3c513bd10875844"
SING_BOX_TAG="v1.14.4"
IPTPROXY_TAG="5.8.1"
WEBLIBRE_SOURCE="${BUILD_ROOT}/WebLibre"
SING_BOX_SOURCE="${BUILD_ROOT}/sing-box"
IPTPROXY_SOURCE="${BUILD_ROOT}/IPtProxy"
OUTPUT_AAR="${ROOT}/app/libs/combined-go.aar"

clone_or_checkout() {
  local url="$1" path="$2" revision="$3"
  if [[ ! -d "$path/.git" ]]; then
    git clone --filter=blob:none "$url" "$path"
  fi
  git -C "$path" fetch --tags --force
  git -C "$path" checkout --detach "$revision"
}

command -v git >/dev/null || { echo "git is required" >&2; exit 1; }
command -v go >/dev/null || { echo "Go 1.26.10+ is required" >&2; exit 1; }
command -v java >/dev/null || { echo "OpenJDK 17 is required" >&2; exit 1; }
: "${ANDROID_NDK_HOME:?Set ANDROID_NDK_HOME to Android NDK 29.0.14206865}"
export GOPRIVATE="${GOPRIVATE:+$GOPRIVATE,}gitlab.torproject.org"

mkdir -p "$BUILD_ROOT" "$(dirname "$OUTPUT_AAR")"
clone_or_checkout "https://github.com/FaFre/WebLibre.git" "$WEBLIBRE_SOURCE" "$WEBLIBRE_COMMIT"
clone_or_checkout "https://github.com/SagerNet/sing-box.git" "$SING_BOX_SOURCE" "$SING_BOX_TAG"
clone_or_checkout "https://github.com/tladesignz/IPtProxy.git" "$IPTPROXY_SOURCE" "$IPTPROXY_TAG"
git -C "$IPTPROXY_SOURCE" submodule update --init --recursive

bash "$WEBLIBRE_SOURCE/native/go_mobile_runtime/scripts/build-android.sh" \
  --sing-box-source "$SING_BOX_SOURCE" \
  --iptproxy-source "$IPTPROXY_SOURCE" \
  --dnstt-source "$IPTPROXY_SOURCE/dnstt" \
  --target android/arm64 \
  --output "$OUTPUT_AAR"

test -s "$OUTPUT_AAR"
echo "Combined gomobile runtime ready: $OUTPUT_AAR"
