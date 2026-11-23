# Lantern Custom — customization policy

This branch is based on the official Lantern source.

## Pinned upstream
- Repository: https://github.com/getlantern/lantern
- Commit: `d9b971b4c79e933fafccf1883e78c9335f51f17e`
- License: GNU GPL-3.0

## Project rules
- Preserve upstream copyright and license notices.
- Keep changes in reviewable commits and document each behavior change.
- Do not bypass subscriptions, payment checks, licensing, authentication, or other access controls.
- Do not embed private server credentials, tokens, or user secrets in source code.
- Validate Android builds and tests before distributing an APK.

## Source import
Run **Actions → Import official Lantern source → Run workflow** on branch `lantern-custom`.
The workflow imports the pinned upstream snapshot into this branch only. It does not modify `main`.
