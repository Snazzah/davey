# Changelog

All notable changes to this project will be documented in this file.

## Unreleased

### Breaking:

- `DaveSession.get_user_ids()` now returns `List[int]` instead of `List[str]`

### Added:

- `DaveSession.process_welcome()` now has an optional `recognized_user_ids` argument that gets checked against the users in the welcome group. (parity with [libdave v1.2.0](https://github.com/discord/libdave/releases/tag/v1.2.0/cpp))

### Fixed:

- Group IDs are now checked when processing welcomes. (parity with [libdave v1.2.0](https://github.com/discord/libdave/releases/tag/v1.2.0/cpp) & [v1.2.1](https://github.com/discord/libdave/releases/tag/v1.2.1/cpp))
- Own commits are only accepted if they exactly match the pending commit.
- Passthrough mode can now only shorten the cipher manager expiry, not extend it. (https://github.com/discord/libdave/commit/48e6232e0884e4774576184b9031c1a9ac19a604)
- Missing nonces that arrive early are now tracked. (https://github.com/discord/libdave/commit/65be1a4476e41219b536dba15ab919f66b2a63b4)
- Duplicate key ratchet installs are now ignored. (https://github.com/discord/libdave/commit/8de72b1f8a2ac3c5a5270755bb8091a62e3c6169)
- `__repr__()` of `DaveSession` and `SigningKeyPair` no longer leaks memory. (whoops)

## 0.1.7 - 2026-10-11

Updated PyO3 so that Python version 3.15 successfully builds

## 0.1.6 - 2026-06-20

Fixed libdave parity, improved reliability in encryption and video processing ([#17](https://github.com/Snazzah/davey/issues/17))

## 0.1.5 - 2026-03-28

Updated internal dependencies to fix vulnerabilities: https://github.com/cryspen/libcrux/security/advisories/GHSA-435g-fcv3-8j26 & https://github.com/cryspen/hpke-rs/security/advisories/GHSA-g433-pq76-6cmf

## 0.1.4 - 2026-03-02

Updated the internal OpenMLS dependency to fix a high severity vulnerability: https://github.com/advisories/GHSA-8x3w-qj7j-gqhf

## 0.1.3 - 2025-12-19

Support for H265, VP8, Vp9 and AV1 encryption.

## 0.1.2 - 2025-11-17

Fixes an issue with enabling passthrough mode and sets the expiry properly.

## 0.1.1 - 2025-09-23

Support for H264 encryption.

## 0.1.0 - 2025-09-08

Initial release.