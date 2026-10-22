//! Ported from libdave
//! [`cpp/test/cryptor_tests.cpp`](https://github.com/discord/libdave/blob/8de72b1f8a2ac3c5a5270755bb8091a62e3c6169/cpp/test/cryptor_tests.cpp)

use std::{sync::Arc, time::Duration};

use crate::{
  cryptor::{
    Codec, MediaType, OPUS_SILENCE_PACKET, clock::Clock, decryptor::Decryptor, encryptor::Encryptor,
  },
  errors::DecryptorDecryptError,
};

use super::common::{RANDOM_BYTES, from_hex, static_key_ratchet};

const USER_ID: &str = "0123456789876543210";
// distinct users stand in for the distinct key domains of an epoch transition
const FIRST_USER_ID: &str = "1111111111111111111";
const SECOND_USER_ID: &str = "2222222222222222222";

fn encrypt_frame(encryptor: &mut Encryptor, frame: &[u8]) -> Vec<u8> {
  let mut encrypted_frame = vec![0u8; frame.len() * 2];
  let mut bytes_written = 0;
  let success = encryptor.encrypt(
    &MediaType::AUDIO,
    Codec::OPUS,
    frame,
    &mut encrypted_frame,
    &mut bytes_written,
  );
  assert!(success);
  encrypted_frame.truncate(bytes_written);
  encrypted_frame
}

fn encrypt_frame_for_user(user_id: &str, frame: &[u8]) -> Vec<u8> {
  let mut encryptor = Encryptor::new();
  encryptor.set_key_ratchet(static_key_ratchet(user_id));
  encrypt_frame(&mut encryptor, frame)
}

fn decrypt_frame(
  decryptor: &mut Decryptor,
  encrypted_frame: &[u8],
) -> Result<usize, DecryptorDecryptError> {
  let mut decrypted_frame = vec![0u8; encrypted_frame.len()];
  decryptor.decrypt(MediaType::AUDIO, encrypted_frame, &mut decrypted_frame)
}

/// libdave: [`CryptorTests.PassthroughTwoBuffers`](https://github.com/discord/libdave/blob/8de72b1f8a2ac3c5a5270755bb8091a62e3c6169/cpp/test/cryptor_tests.cpp#L95)
/// (partially ported due to no passthrough mode)
#[test]
fn passthrough_two_buffers() {
  let incoming_frame = from_hex(RANDOM_BYTES);
  let mut decrypted_frame = vec![0u8; incoming_frame.len()];

  let mut decryptor = Decryptor::new();
  decryptor.transition_to_passthrough_mode(true, 0);

  let bytes_decrypted = decryptor
    .decrypt(MediaType::AUDIO, &incoming_frame, &mut decrypted_frame)
    .expect("unencrypted frame should pass through");

  assert_eq!(bytes_decrypted, incoming_frame.len());
  assert_eq!(decrypted_frame, incoming_frame);
}

/// libdave: [`CryptorTests.SilencePacketPassthrough`](https://github.com/discord/libdave/blob/8de72b1f8a2ac3c5a5270755bb8091a62e3c6169/cpp/test/cryptor_tests.cpp#L130)
#[test]
fn silence_packet_passthrough() {
  let mut decryptor = Decryptor::new();
  decryptor.transition_to_key_ratchet(static_key_ratchet(USER_ID));

  let mut decrypted_frame = vec![0u8; OPUS_SILENCE_PACKET.len()];
  let bytes_written = decryptor
    .decrypt(MediaType::AUDIO, &OPUS_SILENCE_PACKET, &mut decrypted_frame)
    .expect("silence packet should pass through");

  assert_eq!(bytes_written, OPUS_SILENCE_PACKET.len());
  assert_eq!(decrypted_frame, OPUS_SILENCE_PACKET);
}

/// libdave: [`CryptorTests.RandomOpusFrameEncryptDecrypt`](https://github.com/discord/libdave/blob/8de72b1f8a2ac3c5a5270755bb8091a62e3c6169/cpp/test/cryptor_tests.cpp#L149)
#[test]
fn random_opus_frame_encrypt_decrypt() {
  let mut encryptor = Encryptor::new();
  let mut decryptor = Decryptor::new();

  // set static key ratchet for testing
  encryptor.set_key_ratchet(static_key_ratchet(USER_ID));
  decryptor.transition_to_key_ratchet(static_key_ratchet(USER_ID));

  let incoming_frame = from_hex(RANDOM_BYTES);
  let mut encrypted_frame = vec![0u8; incoming_frame.len() * 2];
  let mut decrypted_frame = vec![0u8; incoming_frame.len()];

  // encrypt frame
  let mut bytes_written = 0;
  let success = encryptor.encrypt(
    &MediaType::AUDIO,
    Codec::OPUS,
    &incoming_frame,
    &mut encrypted_frame,
    &mut bytes_written,
  );
  assert!(success);
  assert!(bytes_written >= incoming_frame.len());

  // decrypt frame
  let bytes_decrypted = decryptor
    .decrypt(
      MediaType::AUDIO,
      &encrypted_frame[..bytes_written],
      &mut decrypted_frame,
    )
    .expect("decryption should succeed");
  assert_eq!(bytes_decrypted, incoming_frame.len());
  assert_eq!(decrypted_frame, incoming_frame);
}

/// libdave: [`CryptorTests.DuplicateRatchetInstallRejectsReplay`](https://github.com/discord/libdave/blob/8de72b1f8a2ac3c5a5270755bb8091a62e3c6169/cpp/test/cryptor_tests.cpp#L188)
#[test]
fn duplicate_ratchet_install_rejects_replay() {
  let frame = from_hex(RANDOM_BYTES);
  let encrypted_frame = encrypt_frame_for_user(USER_ID, &frame);

  let mut decryptor = Decryptor::new();
  decryptor.transition_to_key_ratchet(static_key_ratchet(USER_ID));

  assert!(decrypt_frame(&mut decryptor, &encrypted_frame).is_ok());

  // a same-domain re-install must not reset replay protection
  decryptor.transition_to_key_ratchet(static_key_ratchet(USER_ID));

  // libdave: ResultCode::InvalidNonce
  assert!(decrypt_frame(&mut decryptor, &encrypted_frame).is_err());
}

/// libdave: [`CryptorTests.RepeatedRatchetInstallsSingleAcceptance`](https://github.com/discord/libdave/blob/8de72b1f8a2ac3c5a5270755bb8091a62e3c6169/cpp/test/cryptor_tests.cpp#L205)
#[test]
fn repeated_ratchet_installs_single_acceptance() {
  const REINSTALL_COUNT: usize = 50;

  let frame = from_hex(RANDOM_BYTES);
  let encrypted_frame = encrypt_frame_for_user(USER_ID, &frame);

  let mut decryptor = Decryptor::new();
  for _ in 0..REINSTALL_COUNT + 1 {
    decryptor.transition_to_key_ratchet(static_key_ratchet(USER_ID));
  }

  let accepted_count = (0..REINSTALL_COUNT + 2)
    .filter(|_| decrypt_frame(&mut decryptor, &encrypted_frame).is_ok())
    .count();
  assert_eq!(accepted_count, 1);
}

/// libdave: [`CryptorTests.GenuineTransitionStillFallsBackToPreviousRatchet`](https://github.com/discord/libdave/blob/8de72b1f8a2ac3c5a5270755bb8091a62e3c6169/cpp/test/cryptor_tests.cpp#L227)
#[test]
fn genuine_transition_still_falls_back_to_previous_ratchet() {
  let frame = from_hex(RANDOM_BYTES);
  let old_domain_frame = encrypt_frame_for_user(FIRST_USER_ID, &frame);

  let mut decryptor = Decryptor::new();
  decryptor.transition_to_key_ratchet(static_key_ratchet(FIRST_USER_ID));
  decryptor.transition_to_key_ratchet(static_key_ratchet(SECOND_USER_ID));

  // an in-flight frame from before the transition still decrypts via fallback
  assert!(decrypt_frame(&mut decryptor, &old_domain_frame).is_ok());
  // but replaying it is still rejected
  assert!(decrypt_frame(&mut decryptor, &old_domain_frame).is_err());

  let new_domain_frame = encrypt_frame_for_user(SECOND_USER_ID, &frame);
  assert!(decrypt_frame(&mut decryptor, &new_domain_frame).is_ok());
}

/// libdave: [`CryptorTests.TamperedFrameRejected`](https://github.com/discord/libdave/blob/8de72b1f8a2ac3c5a5270755bb8091a62e3c6169/cpp/test/cryptor_tests.cpp#L251)
///
/// Deduplication must not weaken authentication: a tag-tampered frame is rejected,
/// and the genuine frame still decrypts.
#[test]
fn tampered_frame_rejected() {
  let frame = from_hex(RANDOM_BYTES);
  let encrypted_frame = encrypt_frame_for_user(USER_ID, &frame);

  let mut decryptor = Decryptor::new();
  decryptor.transition_to_key_ratchet(static_key_ratchet(USER_ID));

  // corrupt a ciphertext byte so authentication fails
  let mut tampered_frame = encrypted_frame.clone();
  let middle = tampered_frame.len() / 2;
  tampered_frame[middle] ^= 0x01;
  assert!(decrypt_frame(&mut decryptor, &tampered_frame).is_err());

  assert!(decrypt_frame(&mut decryptor, &encrypted_frame).is_ok());
}

/// libdave: [`CryptorTests.DuplicateInstallDoesNotExtendExpiry`](https://github.com/discord/libdave/blob/8de72b1f8a2ac3c5a5270755bb8091a62e3c6169/cpp/test/cryptor_tests.cpp#L268)
#[test]
fn duplicate_install_does_not_extend_expiry() {
  let frame = from_hex(RANDOM_BYTES);

  let mut encryptor = Encryptor::new();
  encryptor.set_key_ratchet(static_key_ratchet(FIRST_USER_ID));
  let first_old_domain_frame = encrypt_frame(&mut encryptor, &frame);
  let second_old_domain_frame = encrypt_frame(&mut encryptor, &frame);

  let clock = Arc::new(Clock::new());
  let mut decryptor = Decryptor::with_clock(clock.clone());
  decryptor.transition_to_key_ratchet(static_key_ratchet(FIRST_USER_ID));
  // a genuine transition gives the previous manager a short expiry
  decryptor.transition_to_key_ratchet(static_key_ratchet(SECOND_USER_ID));

  // halfway through the transition window the previous manager still decrypts
  clock.advance(Duration::from_secs(5));
  // a duplicate install must not extend the previous manager's lifetime
  decryptor.transition_to_key_ratchet(static_key_ratchet(SECOND_USER_ID));
  assert!(decrypt_frame(&mut decryptor, &first_old_domain_frame).is_ok());

  // beyond the original window it must be gone, even though the duplicate
  // install happened later
  clock.advance(Duration::from_secs(6));
  assert!(decrypt_frame(&mut decryptor, &second_old_domain_frame).is_err());
}

/// libdave: [`CryptorTests.DistinctDomainRatchetsAreNotDeduplicated`](https://github.com/discord/libdave/blob/8de72b1f8a2ac3c5a5270755bb8091a62e3c6169/cpp/test/cryptor_tests.cpp#L301)
#[test]
fn distinct_domain_ratchets_are_not_deduplicated() {
  let frame = from_hex(RANDOM_BYTES);
  let first_frame = encrypt_frame_for_user(FIRST_USER_ID, &frame);
  let second_frame = encrypt_frame_for_user(SECOND_USER_ID, &frame);

  let mut decryptor = Decryptor::new();
  decryptor.transition_to_key_ratchet(static_key_ratchet(FIRST_USER_ID));
  decryptor.transition_to_key_ratchet(static_key_ratchet(SECOND_USER_ID));

  assert!(decrypt_frame(&mut decryptor, &first_frame).is_ok());
  assert!(decrypt_frame(&mut decryptor, &second_frame).is_ok());
}
