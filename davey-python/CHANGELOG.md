# Changelog

All notable changes to this project will be documented in this file.

## Unreleased

### Breaking:

- `DaveSession.get_user_ids()` now returns `List[int]` instead of `List[str]`
- `DaveSession.process_commit()` and `DaveSession.process_welcome()` no longer update keys. Call `DaveSession.prepare_transition()` with the transition ID and `protocol_version` afterwards, and the key used to encrypt packets is only switched once that transition is executed with `DaveSession.execute_transition()`, unless the transition ID is 0. (parity with [libdave's sample](https://github.com/discord/libdave/blob/8de72b1f8a2ac3c5a5270755bb8091a62e3c6169/samples/typescript/DaveSessionManager.ts#L85-L114))
- `DaveSession.reinit()` now keeps the current encryption and decryption keys until the next transition replaces them, so `ready` stays `True`. (parity with libdave)

### Added:

- `DaveSession.process_welcome()` now has an optional `recognized_user_ids` argument that gets checked against the users in the welcome group. (parity with [libdave v1.2.0](https://github.com/discord/libdave/releases/tag/v1.2.0/cpp))
- `DaveSession.prepare_transition()` and `DaveSession.execute_transition()` for handling opcodes 21 and 22. Preparing a downgrade to protocol version 0 keeps the current decryption keys usable for 10 seconds.
- `DaveSession.can_encrypt` to check whether the session has a key to encrypt with.
- `EncryptionStats.missing_keys` and `DecryptionStats.missing_keys` for the number of encryptions and decryptions that failed due to a missing key, and `DecryptionStats.invalid_nonces` for the number of decryptions that failed due to an invalid nonce.

### Fixed:

- Enabling passthrough mode now also applies to decryptors created afterwards.
- Group IDs are now checked when processing welcomes. (parity with [libdave v1.2.0](https://github.com/discord/libdave/releases/tag/v1.2.0/cpp) & [v1.2.1](https://github.com/discord/libdave/releases/tag/v1.2.1/cpp))
- Own commits are only accepted if they exactly match the pending commit.
- Passthrough mode can now only shorten the cipher manager expiry, not extend it. (https://github.com/discord/libdave/commit/48e6232e0884e4774576184b9031c1a9ac19a604)
- Decrypting with a newer key generation can now only shorten the expiry of older generations, not extend it. (parity with libdave)
- Missing nonces that arrive early are now tracked. (https://github.com/discord/libdave/commit/65be1a4476e41219b536dba15ab919f66b2a63b4)
- Missing nonces are now limited to 1000 tracked nonces instead of a window of the last 1000 nonces, so older frames can still be decrypted. (https://github.com/discord/libdave/commit/3bdd9fdf1c45b29d45b62e4b228ce627f9b9f707)
- Fixed LEB128 not being read correctly in some cases.
- `DecryptionStats.attempts` now only counts actual decryption attempts, not every key ratchet that was tried. (parity with libdave)
- Duplicate key ratchet installs are now ignored. (https://github.com/discord/libdave/commit/8de72b1f8a2ac3c5a5270755bb8091a62e3c6169)
- Re-installing the encryption key of the current epoch no longer restarts the nonce sequence, which reused nonces. (https://github.com/discord/libdave/commit/d3bac61ff5f0541af3e6751de34b3d5d48349eed)
- `__repr__()` of `DaveSession` and `SigningKeyPair` no longer leaks memory. (whoops)
- Duplicate user IDs are now rejected in proposals, welcomes and commits. (parity with libdave)
- Proposals and commits are now checked for their wire format, epoch, content type and sender, and commits are rejected without queued proposals or with non-reference proposals. (parity with libdave)
- Welcomes are no longer lost when the members being added were proposed before the latest batch of proposals.
- The newest key is now tried first when decrypting.
- Only Opus audio silence packets are passed through.
- Encryption and decryption stats no longer overflow past 32-bit values.
- Reduced buffer allocations in encryption and decryption. ([#18](https://github.com/Snazzah/davey/issues/18))

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