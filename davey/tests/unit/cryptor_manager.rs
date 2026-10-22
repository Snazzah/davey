//! Ported from libdave
//! [`cpp/test/cryptor_manager_tests.cpp`](https://github.com/discord/libdave/blob/8de72b1f8a2ac3c5a5270755bb8091a62e3c6169/cpp/test/cryptor_manager_tests.cpp)

use std::{sync::Arc, time::Duration};

use crate::cryptor::{
  CIPHER_EXPIRY, GENERATION_WRAP, MAX_GENERATION_GAP, MAX_MISSING_NONCES,
  RATCHET_GENERATION_SHIFT_BITS,
  clock::Clock,
  cryptor_manager::{CipherManager, compute_wrapped_big_nonce, compute_wrapped_generation},
};

use super::common::{make_static_sender_key, static_key_ratchet};

const HOUR: Duration = Duration::from_secs(60 * 60);
const MICROSECOND: Duration = Duration::from_micros(1);
/// libdave: `kDefaultTransitionDuration`
const DEFAULT_TRANSITION_DURATION: Duration = Duration::from_secs(10);

fn make_cipher_manager() -> (Arc<Clock>, CipherManager) {
  let clock = Arc::new(Clock::new());
  let cipher_manager =
    CipherManager::new(clock.clone(), static_key_ratchet("12345678901234567890"));
  (clock, cipher_manager)
}

fn nonce(generation: u32, counter: u32) -> u32 {
  (generation << RATCHET_GENERATION_SHIFT_BITS) | counter
}

// Gap can't be larger than the amount of bits allocated for it if we want to handle wraparound
// correctly
const _: () = assert!(
  MAX_GENERATION_GAP < GENERATION_WRAP,
  "Gap can't be larger than wraparound value"
);

/// libdave: [`CryptorManagerTests.CryptorManagerCheckMaxGap`](https://github.com/discord/libdave/blob/8de72b1f8a2ac3c5a5270755bb8091a62e3c6169/cpp/test/cryptor_manager_tests.cpp#L46)
#[test]
fn check_max_gap() {
  let (clock, mut cipher_manager) = make_cipher_manager();
  // Give plenty of room to not trigger the max lifetime generations check
  clock.advance(MAX_GENERATION_GAP * 48 * HOUR);

  let cipher = cipher_manager
    .get_cipher(0)
    .map(|cipher| cipher as *const _);
  assert!(cipher.is_some());
  assert_eq!(
    cipher_manager
      .get_cipher(0)
      .map(|cipher| cipher as *const _),
    cipher
  );
  assert!(cipher_manager.get_cipher(MAX_GENERATION_GAP).is_some());
  assert!(cipher_manager.get_cipher(MAX_GENERATION_GAP + 1).is_none());
  cipher_manager.report_cipher_success(MAX_GENERATION_GAP, nonce(MAX_GENERATION_GAP, 0));
  assert!(cipher_manager.get_cipher(MAX_GENERATION_GAP + 1).is_some());
}

/// libdave: [`CryptorManagerTests.CryptorManagerCheckExpiry`](https://github.com/discord/libdave/blob/8de72b1f8a2ac3c5a5270755bb8091a62e3c6169/cpp/test/cryptor_manager_tests.cpp#L69)
#[test]
fn check_expiry() {
  let (clock, mut cipher_manager) = make_cipher_manager();
  assert!(cipher_manager.get_cipher(0).is_some());
  clock.advance(1_000_000 * HOUR);
  assert!(cipher_manager.get_cipher(0).is_some());
  assert!(cipher_manager.get_cipher(1).is_some());
  cipher_manager.report_cipher_success(1, nonce(1, 0));
  clock.advance(CIPHER_EXPIRY - MICROSECOND);
  assert!(cipher_manager.get_cipher(0).is_some());
  clock.advance(2 * MICROSECOND);
  assert!(cipher_manager.get_cipher(0).is_none());
}

/// libdave: [`CryptorManagerTests.CryptorManagerUpdateExpiryOnlyShortens`](https://github.com/discord/libdave/blob/8de72b1f8a2ac3c5a5270755bb8091a62e3c6169/cpp/test/cryptor_manager_tests.cpp#L89)
#[test]
fn update_expiry_only_shortens() {
  let (clock, mut cipher_manager) = make_cipher_manager();

  // A cryptor manager that has not been transitioned away from never expires
  clock.advance(1_000_000 * HOUR);
  assert!(!cipher_manager.is_expired());

  // The first transition away from this ratchet schedules its expiry
  cipher_manager.update_expiry(clock.elapsed() + DEFAULT_TRANSITION_DURATION);
  clock.advance(DEFAULT_TRANSITION_DURATION / 2);
  assert!(!cipher_manager.is_expired());

  // A later transition must not push the already scheduled expiry further out
  cipher_manager.update_expiry(clock.elapsed() + DEFAULT_TRANSITION_DURATION);
  clock.advance(DEFAULT_TRANSITION_DURATION / 2 + MICROSECOND);
  assert!(cipher_manager.is_expired());

  // A later transition with a shorter window still shortens the expiry
  let mut short_lived =
    CipherManager::new(clock.clone(), static_key_ratchet("12345678901234567890"));
  short_lived.update_expiry(clock.elapsed() + DEFAULT_TRANSITION_DURATION);
  short_lived.update_expiry(clock.elapsed() + Duration::from_secs(1));
  clock.advance(Duration::from_secs(1) + MICROSECOND);
  assert!(short_lived.is_expired());
}

/// libdave: [`CryptorManagerTests.CryptorManagerDeleteOldKeys`](https://github.com/discord/libdave/blob/8de72b1f8a2ac3c5a5270755bb8091a62e3c6169/cpp/test/cryptor_manager_tests.cpp#L116)
#[test]
fn delete_old_keys() {
  let (clock, mut cipher_manager) = make_cipher_manager();
  // Give plenty of room to not trigger the max lifetime generations check
  clock.advance(MAX_GENERATION_GAP * 48 * HOUR);

  assert!(cipher_manager.get_cipher(0).is_some());
  assert!(cipher_manager.get_cipher(5).is_some());
  cipher_manager.report_cipher_success(5, nonce(5, 0));
  clock.advance(CIPHER_EXPIRY + MICROSECOND);
  assert!(cipher_manager.get_cipher(5).is_some());

  // libdave expects DeleteKey(0..=4) on the ratchet here; the observable effect is that the
  // older generations can no longer be used
  for generation in 0..5 {
    assert!(cipher_manager.get_cipher(generation).is_none());
  }
}

/// libdave: [`CryptorManagerTests.CryptorManagerGenerationWrap`](https://github.com/discord/libdave/blob/8de72b1f8a2ac3c5a5270755bb8091a62e3c6169/cpp/test/cryptor_manager_tests.cpp#L139)
#[test]
fn generation_wrap() {
  assert_eq!(compute_wrapped_generation(0, 0), 0);
  assert_eq!(compute_wrapped_generation(0, 1), 1);
  assert_eq!(compute_wrapped_generation(0, 250), 250);

  assert_eq!(
    compute_wrapped_generation(11 * GENERATION_WRAP + 42, 42),
    11 * GENERATION_WRAP + 42
  );
  assert_eq!(
    compute_wrapped_generation(11 * GENERATION_WRAP + 42, 50),
    11 * GENERATION_WRAP + 50
  );
  assert_eq!(
    compute_wrapped_generation(11 * GENERATION_WRAP + 42, 10),
    12 * GENERATION_WRAP + 10
  );
}

/// libdave: [`CryptorManagerTests.CryptorManagerBigNonce`](https://github.com/discord/libdave/blob/8de72b1f8a2ac3c5a5270755bb8091a62e3c6169/cpp/test/cryptor_manager_tests.cpp#L153)
#[test]
fn big_nonce() {
  const SHIFT: usize = RATCHET_GENERATION_SHIFT_BITS;

  assert_eq!(compute_wrapped_big_nonce(0, 0), 0);
  assert_eq!(compute_wrapped_big_nonce(0, 1), 1);
  assert_eq!(compute_wrapped_big_nonce(0, 250), 250);

  assert_eq!(compute_wrapped_big_nonce(11, 10), (11 << SHIFT) | 10);
  assert_eq!(compute_wrapped_big_nonce(11, 42), (11 << SHIFT) | 42);
  assert_eq!(compute_wrapped_big_nonce(11, 50), (11 << SHIFT) | 50);

  assert_eq!(
    compute_wrapped_big_nonce(11, (2 << SHIFT) | 34),
    (11 << SHIFT) | 34
  );
  assert_eq!(
    compute_wrapped_big_nonce(11, (37 << SHIFT) | 139),
    (11 << SHIFT) | 139
  );
  assert_eq!(
    compute_wrapped_big_nonce(11, (89 << SHIFT) | 294),
    (11 << SHIFT) | 294
  );
}

/// libdave: [`CryptorManagerTests.CryptorManagerCapturesDomainIdentity`](https://github.com/discord/libdave/blob/8de72b1f8a2ac3c5a5270755bb8091a62e3c6169/cpp/test/cryptor_manager_tests.cpp#L171)
///
/// libdave's `StaticKeyRatchet` uses the user ID string as its domain identity. davey's stand-in
/// is a [`HashRatchet`](crate::cryptor::hash_ratchet::HashRatchet), whose domain identity is its
/// base secret, i.e. the static sender key.
#[test]
fn captures_domain_identity() {
  let clock = Arc::new(Clock::new());

  let user_id = "12345678901234567890";
  let cipher_manager = CipherManager::new(clock, static_key_ratchet(user_id));
  assert_eq!(
    cipher_manager.domain_identity(),
    make_static_sender_key(user_id)
  );
}

/// libdave: [`CryptorManagerTests.CryptorManagerNoReprocess`](https://github.com/discord/libdave/blob/8de72b1f8a2ac3c5a5270755bb8091a62e3c6169/cpp/test/cryptor_manager_tests.cpp#L181)
#[test]
fn no_reprocess() {
  let (clock, mut cipher_manager) = make_cipher_manager();
  // Give plenty of room to not trigger the max lifetime generations check
  clock.advance(MAX_GENERATION_GAP * 48 * HOUR);

  assert!(cipher_manager.get_cipher(0).is_some());

  assert!(cipher_manager.can_process_nonce(0, 0));
  assert!(cipher_manager.can_process_nonce(0, 1));
  assert!(cipher_manager.can_process_nonce(0, 2));
  assert!(cipher_manager.can_process_nonce(0, 3));
  assert!(cipher_manager.can_process_nonce(0, u32::MAX));
  cipher_manager.report_cipher_success(0, 0);
  assert!(!cipher_manager.can_process_nonce(0, 0));
  assert!(cipher_manager.can_process_nonce(0, 1));
  cipher_manager.report_cipher_success(0, 1);
  cipher_manager.report_cipher_success(0, 2);
  cipher_manager.report_cipher_success(0, 5);
  cipher_manager.report_cipher_success(0, 7);
  assert!(!cipher_manager.can_process_nonce(0, 0));
  assert!(!cipher_manager.can_process_nonce(0, 1));
  assert!(!cipher_manager.can_process_nonce(0, 2));
  assert!(!cipher_manager.can_process_nonce(0, 5));
  assert!(!cipher_manager.can_process_nonce(0, 7));
  assert!(cipher_manager.can_process_nonce(0, 3));
  assert!(cipher_manager.can_process_nonce(0, 4));
  assert!(cipher_manager.can_process_nonce(0, 6));
  assert!(cipher_manager.can_process_nonce(0, 8));
  cipher_manager.report_cipher_success(0, 4);
  assert!(cipher_manager.can_process_nonce(0, 3));
  assert!(!cipher_manager.can_process_nonce(0, 4));
  assert!(cipher_manager.can_process_nonce(0, 6));
  cipher_manager.report_cipher_success(0, 6);
  assert!(cipher_manager.can_process_nonce(0, 3));
  assert!(!cipher_manager.can_process_nonce(0, 6));
  cipher_manager.report_cipher_success(0, 10 + MAX_MISSING_NONCES as u32);
  assert!(!cipher_manager.can_process_nonce(0, 3));
  assert!(!cipher_manager.can_process_nonce(0, 7));
  assert!(!cipher_manager.can_process_nonce(0, 8));
  assert!(!cipher_manager.can_process_nonce(0, 9));
  assert!(cipher_manager.can_process_nonce(0, 10));
  assert!(cipher_manager.can_process_nonce(0, 11));
}

/// libdave: [`CryptorManagerTests.CryptorManagerEarlyMissingNonces`](https://github.com/discord/libdave/blob/8de72b1f8a2ac3c5a5270755bb8091a62e3c6169/cpp/test/cryptor_manager_tests.cpp#L231)
#[test]
fn early_missing_nonces() {
  let (_clock, mut cipher_manager) = make_cipher_manager();

  // The first nonce we see is not the first nonce that was generated: the ones before it are
  // missing, not non-existent, so they must still be processable if they arrive late.
  cipher_manager.report_cipher_success(0, 3);
  assert!(cipher_manager.can_process_nonce(0, 0));
  assert!(cipher_manager.can_process_nonce(0, 1));
  assert!(cipher_manager.can_process_nonce(0, 2));
  assert!(!cipher_manager.can_process_nonce(0, 3));
  assert!(cipher_manager.can_process_nonce(0, 4));

  // Late arrivals are consumed one by one, leaving the others alone.
  cipher_manager.report_cipher_success(0, 1);
  assert!(cipher_manager.can_process_nonce(0, 0));
  assert!(!cipher_manager.can_process_nonce(0, 1));
  assert!(cipher_manager.can_process_nonce(0, 2));

  cipher_manager.report_cipher_success(0, 0);
  cipher_manager.report_cipher_success(0, 2);
  assert!(!cipher_manager.can_process_nonce(0, 0));
  assert!(!cipher_manager.can_process_nonce(0, 2));
  assert!(cipher_manager.can_process_nonce(0, 4));
}

/// libdave: [`CryptorManagerTests.CryptorManagerEarlyMissingNoncesStartAtZero`](https://github.com/discord/libdave/blob/8de72b1f8a2ac3c5a5270755bb8091a62e3c6169/cpp/test/cryptor_manager_tests.cpp#L260)
#[test]
fn early_missing_nonces_start_at_zero() {
  let (_clock, mut cipher_manager) = make_cipher_manager();

  // Starting at nonce 0 leaves nothing missing behind it.
  cipher_manager.report_cipher_success(0, 0);
  assert!(!cipher_manager.can_process_nonce(0, 0));
  assert!(cipher_manager.can_process_nonce(0, 1));
}

/// libdave: [`CryptorManagerTests.CryptorManagerEarlyMissingNoncesCapped`](https://github.com/discord/libdave/blob/8de72b1f8a2ac3c5a5270755bb8091a62e3c6169/cpp/test/cryptor_manager_tests.cpp#L273)
#[test]
fn early_missing_nonces_capped() {
  let (_clock, mut cipher_manager) = make_cipher_manager();

  // A very late stream start only tracks the most recent MAX_MISSING_NONCES nonces.
  const FIRST_NONCE: u32 = MAX_MISSING_NONCES as u32 + 5;
  cipher_manager.report_cipher_success(0, FIRST_NONCE);
  assert!(!cipher_manager.can_process_nonce(0, 0));
  assert!(!cipher_manager.can_process_nonce(0, 4));
  assert!(cipher_manager.can_process_nonce(0, 5));
  assert!(cipher_manager.can_process_nonce(0, FIRST_NONCE - 1));
  assert!(!cipher_manager.can_process_nonce(0, FIRST_NONCE));
  assert!(cipher_manager.can_process_nonce(0, FIRST_NONCE + 1));
}

/// libdave: [`CryptorManagerTests.CryptorManagerEarlyMissingNoncesAcrossGenerations`](https://github.com/discord/libdave/blob/8de72b1f8a2ac3c5a5270755bb8091a62e3c6169/cpp/test/cryptor_manager_tests.cpp#L291)
#[test]
fn early_missing_nonces_across_generations() {
  let (_clock, mut cipher_manager) = make_cipher_manager();

  // The bootstrap gap is measured on the wrapped big nonce, so an early generation-0 packet
  // arriving after a generation-1 one is still processable.
  const FIRST_NONCE: u32 = (1 << RATCHET_GENERATION_SHIFT_BITS) | 2;
  cipher_manager.report_cipher_success(1, FIRST_NONCE);
  assert!(cipher_manager.can_process_nonce(1, FIRST_NONCE - 1));
  assert!(!cipher_manager.can_process_nonce(1, FIRST_NONCE));
  assert!(cipher_manager.can_process_nonce(0, (1 << RATCHET_GENERATION_SHIFT_BITS) - 1));
}
