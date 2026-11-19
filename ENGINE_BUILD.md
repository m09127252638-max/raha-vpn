# Native Android engine build

The Android native engine is built from pinned upstream source. The build combines XTLS/libXray (Xray-core) and IPtProxy (obfs4 transport) into **one gomobile AAR and one Go runtime**. This avoids duplicate gomobile native libraries and incompatible Go runtimes in one Android process.

Pinned source revisions:

- libXray v26.11.9: `5a0f7d8d1c28b34afb5727b04b26a10f6dbac7e3`
- IPtProxy: `b7f48914e10de6a198510e843e1a7d8f56f658e5`
- IPtProxy's dnstt submodule is pinned by that IPtProxy commit.

Toolchain:

- Go 1.27.3
- JDK 17
- Android SDK platform 35
- Android NDK 28.0.13004108
- Android API 24 minimum
- gomobile `v0.0.0-20261117202452-47699113848a`

The CI script builds only `arm64-v8a`, matching the app's current ABI split, and creates `app/libs/libXray.aar`. The AAR is generated during CI and is not committed to Git.

Run from the repository root:

```bash
bash scripts/build-libxray-android.sh
```

The script verifies both source revisions and checks that the resulting AAR contains the Xray API, the obfs4 transport controller, and the arm64 native library. Building this engine is not by itself proof of a working VPN; the Android VpnService, TUN file descriptor, socket protection, DNS routing, and connection lifecycle must still be integrated and tested.
