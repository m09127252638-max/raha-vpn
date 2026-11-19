# Native Android engine build

The Android client uses the official sing-box `libbox` binding. The generated AAR is intentionally not committed because it is a large native artifact.

The build script pins the upstream `v1.14.4` tag to commit `c005f35300ce76427dc285481ec5695f5b179cd2` and builds only `android/arm64`, matching the app's current APK ABI.

Requirements:

- JDK 17
- Go 1.25.5
- Android SDK platform 35
- Android NDK 28.0.13004108
- SagerNet's `gomobile` and `gobind` v0.1.12 (installed by the script)

Run from the repository root:

```bash
bash scripts/build-libbox-android.sh
```

The script writes the generated file to `app/libs/libbox.aar`. It verifies the upstream source commit and prints the AAR SHA-256. The current CI job runs this build as a toolchain verification step; the app does not yet start a full-device VPN until the Android `VpnService` lifecycle and libbox platform adapter are integrated and tested.

CI uses `android-actions/setup-android@v3` with only `platform-tools` requested, then installs the pinned SDK platform and NDK directly. This avoids Google's removed legacy `tools` SDK package.
