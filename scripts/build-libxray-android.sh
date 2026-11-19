#!/usr/bin/env bash
set -euo pipefail

# Build one gomobile runtime containing both Xray/libXray and IPtProxy.
# Keeping both packages in one AAR avoids duplicate libgojni.so files and
# incompatible independent Go runtimes in the Android process.
readonly LIBXRAY_COMMIT="5a0f7d8d1c28b34afb5727b04b26a10f6dbac7e3"
readonly IPTPROXY_COMMIT="b7f48914e10de6a198510e843e1a7d8f56f658e5"
readonly GOMOBILE_VERSION="v0.0.0-20261117202452-47699113848a"
readonly LIBXRAY_DIR="${RUNNER_TEMP:-/tmp}/libXray"
readonly IPTPROXY_DIR="${RUNNER_TEMP:-/tmp}/IPtProxy"

command -v go >/dev/null
command -v git >/dev/null
command -v python3 >/dev/null
: "${ANDROID_HOME:?ANDROID_HOME must point to the installed Android SDK}"

if [[ ! -d "${LIBXRAY_DIR}/.git" ]]; then
  git clone --filter=blob:none https://github.com/XTLS/libXray.git "${LIBXRAY_DIR}"
fi
git -C "${LIBXRAY_DIR}" checkout --detach "${LIBXRAY_COMMIT}"
actual_libxray="$(git -C "${LIBXRAY_DIR}" rev-parse HEAD)"
[[ "${actual_libxray}" == "${LIBXRAY_COMMIT}" ]]

if [[ ! -d "${IPTPROXY_DIR}/.git" ]]; then
  git clone --filter=blob:none https://github.com/tladesignz/IPtProxy.git "${IPTPROXY_DIR}"
fi
git -C "${IPTPROXY_DIR}" checkout --detach "${IPTPROXY_COMMIT}"
git -C "${IPTPROXY_DIR}" submodule update --init --recursive
actual_iptproxy="$(git -C "${IPTPROXY_DIR}" rev-parse HEAD)"
[[ "${actual_iptproxy}" == "${IPTPROXY_COMMIT}" ]]

# Vendor only the two source files for the obfs4 client transport. Its dnstt
# dependency remains a separate, pinned local Go module from the same commit.
mkdir -p "${LIBXRAY_DIR}/third_party/IPtProxy/IPtProxy.go"
find "${IPTPROXY_DIR}/IPtProxy.go" -maxdepth 1 -type f -name '*.go' ! -name '*_test.go' \
  -exec cp {} "${LIBXRAY_DIR}/third_party/IPtProxy/IPtProxy.go/" \;
rm -rf "${LIBXRAY_DIR}/third_party/IPtProxy/dnstt"
cp -a "${IPTPROXY_DIR}/dnstt" "${LIBXRAY_DIR}/third_party/IPtProxy/dnstt"

cat > "${LIBXRAY_DIR}/iptproxy_bridge_android.go" <<'GO'
 //go:build android

package libXray

import (
	"errors"

	iptproxy "github.com/xtls/libxray/third_party/IPtProxy/IPtProxy.go"
)

// PTController exposes only the obfs4 client transport needed by the Android app.
// The underlying IPtProxy package is compiled into this same gomobile runtime.
type PTController struct {
	controller *iptproxy.Controller
}

func NewPTController(stateDir string) (*PTController, error) {
	if stateDir == "" {
		return nil, errors.New("missing pluggable-transport state directory")
	}
	controller := iptproxy.NewController(stateDir, false, false, "ERROR", nil)
	if controller == nil {
		return nil, errors.New("failed to initialize obfs4 transport controller")
	}
	return &PTController{controller: controller}, nil
}

func (c *PTController) StartObfs4() (string, error) {
	if c == nil || c.controller == nil {
		return "", errors.New("obfs4 transport controller is not initialized")
	}
	if err := c.controller.Start(iptproxy.Obfs4, ""); err != nil {
		return "", err
	}
	address := c.controller.LocalAddress(iptproxy.Obfs4)
	if address == "" {
		c.controller.Stop(iptproxy.Obfs4)
		return "", errors.New("obfs4 transport did not create a local SOCKS listener")
	}
	return address, nil
}

func (c *PTController) StopObfs4() {
	if c != nil && c.controller != nil {
		c.controller.Stop(iptproxy.Obfs4)
	}
}

func (c *PTController) Close() {
	c.StopObfs4()
}
GO
# Remove the leading space before the Go build constraint.
sed -i 's/^ //g' "${LIBXRAY_DIR}/iptproxy_bridge_android.go"

# The root module must resolve dnstt from the exact IPtProxy submodule checkout.
(
  cd "${LIBXRAY_DIR}"
  go mod edit -replace=www.bamsoftware.com/git/dnstt.git=./third_party/IPtProxy/dnstt
)

# Limit the native AAR to the app's only packaged ABI and use Android's cgo resolver.
python3 - "${LIBXRAY_DIR}/build/app/android.py" <<'PY'
from pathlib import Path
import sys

path = Path(sys.argv[1])
source = path.read_text()
old = '                    "android",\n                    "-androidapi",'
new = '                    "android/arm64",\n                    "-androidapi",'
if old not in source:
    raise SystemExit("Could not find the pinned libXray Android target argument")
source = source.replace(old, new, 1)
old = '                    "-trimpath",\n                    "-ldflags='
new = '                    "-trimpath",\n                    "-tags=netcgo",\n                    "-ldflags='
if old not in source:
    raise SystemExit("Could not find the libXray gomobile build flags")
path.write_text(source.replace(old, new, 1))
PY

(
  cd "${LIBXRAY_DIR}"
  export GOPRIVATE="gitlab.torproject.org"
  export LIBXRAY_ANDROID_API="24"
  export LIBXRAY_GOMOBILE_VERSION="${GOMOBILE_VERSION}"
  python3 build/main.py android
)

test -s "${LIBXRAY_DIR}/libXray.aar"
python3 - "${LIBXRAY_DIR}/libXray.aar" <<'PY'
from zipfile import ZipFile
import io
import sys

aar_path = sys.argv[1]
with ZipFile(aar_path) as aar:
    names = set(aar.namelist())
    native = "jni/arm64-v8a/libgojni.so"
    if native not in names:
        raise SystemExit(f"Missing native engine library: {native}")
    classes = aar.read("classes.jar")
with ZipFile(io.BytesIO(classes)) as jar:
    class_names = jar.namelist()
    required = {
        "libXray/LibXray.class",
        "libXray/PTController.class",
        "libXray/DialerController.class",
    }
    missing = required.difference(class_names)
    if missing:
        raise SystemExit("Generated AAR is missing expected gomobile classes: " + ", ".join(sorted(missing)))
PY

mkdir -p app/libs
install -m 0644 "${LIBXRAY_DIR}/libXray.aar" app/libs/libXray.aar
sha256sum app/libs/libXray.aar
