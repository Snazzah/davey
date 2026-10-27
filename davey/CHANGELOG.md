# Changelog

All notable changes to this project will be documented in this file.

## Unreleased

### Breaking:

- `DaveSession::process_commit` and `DaveSession::process_welcome` no longer update keys. Call `DaveSession::prepare_transition` with the transition ID and `protocol_version` afterwards, and the key used to encrypt packets is only switched once that transition is executed with `DaveSession::execute_transition`, unless the transition ID is 0. (parity with [libdave's sample](https://github.com/discord/libdave/blob/8de72b1f8a2ac3c5a5270755bb8091a62e3c6169/samples/typescript/DaveSessionManager.ts#L85-L114))
- `DaveSession::reinit` now keeps the current encryption and decryption keys until the next transition replaces them, so `is_ready` stays `true`. (parity with libdave)
- `DaveSession::process_welcome` now takes a `recognized_user_ids` argument that gets checked against the users in the welcome group. (parity with [libdave v1.2.0](https://github.com/discord/libdave/releases/tag/v1.2.0/cpp))
- `EncryptionStats` and `DecryptionStats` fields are now `u64`. (parity with libdave)
- `EncryptError::EncryptionFailed` now contains an `EncryptorEncryptError`.
- `DecryptorDecryptError::NoValidCryptorFound` was replaced with more specific errors: `MissingKeyRatchet`, `InvalidNonce`, `MissingCryptor` and `DecryptionFailure`.

### Added:

- `DaveSession::prepare_transition` and `DaveSession::execute_transition` for handling opcodes 21 and 22. Preparing a downgrade to protocol version 0 keeps the current decryption keys usable for 10 seconds.
- `DaveSession::can_encrypt` to check whether the session has a key to encrypt with.
- `DaveSession::encrypt_into` and `DaveSession::decrypt_into` to encrypt and decrypt into your own buffer, so it can be reused between packets.
- `EncryptionStats::missing_keys` and `DecryptionStats::missing_keys` for the number of encryptions and decryptions that failed due to a missing key, and `DecryptionStats::invalid_nonces` for the number of decryptions that failed due to an invalid nonce.

### Fixed:

- Enabling passthrough mode now also applies to decryptors created afterwards.
- Group IDs are now checked when processing welcomes. (parity with [libdave v1.2.0](https://github.com/discord/libdave/releases/tag/v1.2.0/cpp) & [v1.2.1](https://github.com/discord/libdave/releases/tag/v1.2.1/cpp))
- Own commits are only accepted if they exactly match the pending commit.
- Passthrough mode can now only shorten the cipher manager expiry, not extend it. (ref: https://github.com/discord/libdave/commit/48e6232e0884e4774576184b9031c1a9ac19a604)
- Decrypting with a newer key generation can now only shorten the expiry of older generations, not extend it. (parity with libdave)
- Missing nonces that arrive early are now tracked. (ref: https://github.com/discord/libdave/commit/65be1a4476e41219b536dba15ab919f66b2a63b4)
- Missing nonces are now limited to 1000 tracked nonces instead of a window of the last 1000 nonces, so older frames can still be decrypted. (ref: https://github.com/discord/libdave/commit/3bdd9fdf1c45b29d45b62e4b228ce627f9b9f707)
- Fixed LEB128 not being read correctly in some cases.
- `DecryptionStats::attempts` now only counts actual decryption attempts, not every key ratchet that was tried. (parity with libdave)
- Duplicate key ratchet installs are now ignored. (ref: https://github.com/discord/libdave/commit/8de72b1f8a2ac3c5a5270755bb8091a62e3c6169)
- Re-installing the encryption key of the current epoch no longer restarts the nonce sequence, which reused nonces. (ref: https://github.com/discord/libdave/commit/d3bac61ff5f0541af3e6751de34b3d5d48349eed)
- Duplicate user IDs are now rejected in proposals, welcomes and commits. (parity with libdave)
- Proposals and commits are now checked for their wire format, epoch, content type and sender, and commits are rejected without queued proposals or with non-reference proposals. (parity with libdave)
- Welcomes are no longer lost when the members being added were proposed before the latest batch of proposals.
- The newest key is now tried first when decrypting.
- Only Opus audio silence packets are passed through.
- Reduced buffer allocations in encryption and decryption. ([#18](https://github.com/Snazzah/davey/issues/18))

## 0.1.0 - 2025-12-19

Initial release.
