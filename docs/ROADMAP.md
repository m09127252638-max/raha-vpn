# Engineering roadmap

## Phase 0 — clean foundation
- [x] Create an isolated `lantern-custom` branch in the existing repository.
- [x] Replace the Raha VPN file tree on this branch with a clean project foundation.
- [x] Record the official Lantern upstream and its GPL-3.0 licensing.
- [ ] Import a pinned upstream source snapshot.

## Phase 1 — reproducible baseline
- [ ] Document Flutter, Go, Java, and Android SDK versions from the pinned upstream commit.
- [ ] Configure CI to build the Android app without custom changes.
- [ ] Run upstream tests and save the baseline results.

## Phase 2 — customization
- [ ] Define the requested customization list against actual upstream code.
- [ ] Implement each change in a separate, reviewable commit.
- [ ] Add tests and update documentation for every behavior change.

## Phase 3 — release
- [ ] Verify debug and release builds.
- [ ] Verify ABI support and Android permissions.
- [ ] Produce and test an APK before sharing it.
