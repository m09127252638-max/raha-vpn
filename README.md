# Lantern Custom

A clean Android-focused customization project based on the official, open-source [Lantern](https://github.com/getlantern/lantern) codebase.

> **Project status:** Initial repository reset and project foundation. The upstream source has been inspected, but has **not yet been imported or built in this branch**. No APK is available yet.

## Direction

- Start from the official Lantern architecture rather than the previous Raha VPN implementation.
- Keep upstream copyright notices and the GNU GPL-3.0 license requirements.
- Make user-facing, documented customizations without bypassing paid subscriptions, licensing checks, or access controls.
- Keep networking changes testable and diagnosable; never ship hard-coded private endpoints or credentials.
- Target Android first. The upstream repository currently uses Flutter for its application UI and Go for core networking components.

## Upstream

- Repository: https://github.com/getlantern/lantern
- Branch inspected: `main`
- Upstream license: GNU General Public License v3.0 (see [LICENSE](LICENSE))

## Next engineering steps

1. Import and pin a specific upstream commit, preserving all upstream notices and required source files.
2. Reproduce the official Android build in CI before making changes.
3. Establish a baseline build/test report.
4. Apply one small customization at a time, with tests and a changelog entry.

## Build status

Not buildable yet: this branch currently contains project documentation only. The upstream source import and Android build verification are the next steps.
