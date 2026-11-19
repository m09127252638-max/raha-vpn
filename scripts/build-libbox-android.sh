#!/usr/bin/env bash
set -euo pipefail

# Build the official sing-box libbox Android binding from a pinned upstream commit.
# This keeps the large generated AAR out of Git while making CI builds reproducible.
readonly SING_BOX_TAG="v1.14.4"
readonly SING_BOX_COMMIT="c005f35300ce76427dc285481ec5695f5b179cd2"
readonly GOMOBILE_VERSION="v0.1.12"
readonly ENGINE_DIR="${RUNNER_TEMP:-/tmp}/sing-box-${SING_BOX_TAG}"

command -v go >/dev/null
command -v git >/dev/null
: "${ANDROID_HOME:?ANDROID_HOME must point to the installed Android SDK}"

if [[ ! -d "${ENGINE_DIR}/.git" ]]; then
  git clone --depth 1 --branch "${SING_BOX_TAG}" https://github.com/SagerNet/sing-box.git "${ENGINE_DIR}"
fi

actual_commit="$(git -C "${ENGINE_DIR}" rev-parse HEAD)"
if [[ "${actual_commit}" != "${SING_BOX_COMMIT}" ]]; then
  echo "Unexpected sing-box source revision: ${actual_commit}" >&2
  exit 1
fi

go install "github.com/sagernet/gomobile/cmd/gomobile@${GOMOBILE_VERSION}"
go install "github.com/sagernet/gomobile/cmd/gobind@${GOMOBILE_VERSION}"

(
  cd "${ENGINE_DIR}"
  go run ./cmd/internal/build_libbox -target android -platform android/arm64
)

test -s "${ENGINE_DIR}/libbox.aar"
mkdir -p app/libs
install -m 0644 "${ENGINE_DIR}/libbox.aar" app/libs/libbox.aar
sha256sum app/libs/libbox.aar
