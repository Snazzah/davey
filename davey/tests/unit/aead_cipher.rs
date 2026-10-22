//! Ported from libdave
//! [`cpp/test/xssl_cryptor_tests.cpp`](https://github.com/discord/libdave/blob/8de72b1f8a2ac3c5a5270755bb8091a62e3c6169/cpp/test/xssl_cryptor_tests.cpp)

use crate::cryptor::{AES_GCM_128_NONCE_BYTES, aead_cipher::AeadCipher};

use super::common::make_static_sender_key;

const PLAINTEXT_SIZE: usize = 1024;

/// libdave: [`XSSLCryptorTests.XSSLEncryptDecrypt`](https://github.com/discord/libdave/blob/8de72b1f8a2ac3c5a5270755bb8091a62e3c6169/cpp/test/xssl_cryptor_tests.cpp#L26)
#[test]
fn encrypt_decrypt() {
  let plaintext = vec![0u8; PLAINTEXT_SIZE];
  let additional_data = vec![0u8; PLAINTEXT_SIZE];
  let nonce = vec![0u8; AES_GCM_128_NONCE_BYTES];

  let mut cipher = AeadCipher::new(&make_static_sender_key("12345678901234567890")).unwrap();

  let mut buffer = plaintext.clone();
  let tag = cipher
    .encrypt(&mut buffer, &nonce, &additional_data)
    .expect("encryption should succeed");

  // The ciphertext should not be the same as the plaintext
  assert_ne!(buffer, plaintext);

  cipher
    .decrypt(&mut buffer, &nonce, &additional_data, &tag)
    .expect("decryption should succeed");

  // The plaintext should be the same as the original plaintext
  assert_eq!(buffer, plaintext);
}

/// libdave: [`XSSLCryptorTests.XSSLAdditionalDataAuth`](https://github.com/discord/libdave/blob/8de72b1f8a2ac3c5a5270755bb8091a62e3c6169/cpp/test/xssl_cryptor_tests.cpp#L62)
#[test]
fn additional_data_auth() {
  let mut additional_data = vec![0u8; PLAINTEXT_SIZE];
  let nonce = vec![0u8; AES_GCM_128_NONCE_BYTES];

  let mut cipher = AeadCipher::new(&make_static_sender_key("12345678901234567890")).unwrap();

  let mut buffer = vec![0u8; PLAINTEXT_SIZE];
  let tag = cipher
    .encrypt(&mut buffer, &nonce, &additional_data)
    .expect("encryption should succeed");

  // We modify the additional data before decryption
  additional_data[0] = 1;

  assert!(
    cipher
      .decrypt(&mut buffer, &nonce, &additional_data, &tag)
      .is_err()
  );
}

/// libdave: [`XSSLCryptorTests.XSSLKeyDiff`](https://github.com/discord/libdave/blob/8de72b1f8a2ac3c5a5270755bb8091a62e3c6169/cpp/test/xssl_cryptor_tests.cpp#L95)
#[test]
fn key_diff() {
  let additional_data = vec![0u8; PLAINTEXT_SIZE];
  let nonce = vec![0u8; AES_GCM_128_NONCE_BYTES];

  let mut cipher1 = AeadCipher::new(&make_static_sender_key("12345678901234567890")).unwrap();
  let mut cipher2 = AeadCipher::new(&make_static_sender_key("09876543210987654321")).unwrap();

  let mut ciphertext1 = vec![0u8; PLAINTEXT_SIZE];
  let mut ciphertext2 = vec![0u8; PLAINTEXT_SIZE];
  assert!(
    cipher1
      .encrypt(&mut ciphertext1, &nonce, &additional_data)
      .is_ok()
  );
  assert!(
    cipher2
      .encrypt(&mut ciphertext2, &nonce, &additional_data)
      .is_ok()
  );

  assert_ne!(ciphertext1, ciphertext2);
}

/// libdave: [`XSSLCryptorTests.XSSLNonceDiff`](https://github.com/discord/libdave/blob/8de72b1f8a2ac3c5a5270755bb8091a62e3c6169/cpp/test/xssl_cryptor_tests.cpp#L129)
#[test]
fn nonce_diff() {
  let additional_data = vec![0u8; PLAINTEXT_SIZE];
  let nonce1 = vec![0u8; AES_GCM_128_NONCE_BYTES];
  let nonce2 = vec![1u8; AES_GCM_128_NONCE_BYTES];

  let mut cipher = AeadCipher::new(&make_static_sender_key("12345678901234567890")).unwrap();

  let mut ciphertext1 = vec![0u8; PLAINTEXT_SIZE];
  let mut ciphertext2 = vec![0u8; PLAINTEXT_SIZE];
  assert!(
    cipher
      .encrypt(&mut ciphertext1, &nonce1, &additional_data)
      .is_ok()
  );
  assert!(
    cipher
      .encrypt(&mut ciphertext2, &nonce2, &additional_data)
      .is_ok()
  );

  assert_ne!(ciphertext1, ciphertext2);
}
