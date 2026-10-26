use std::{collections::HashMap, time::Instant};

use tracing::warn;

use crate::errors::EncryptorEncryptError;

use super::{
  aead_cipher::AeadCipher,
  codec_utils::validate_encrypted_frame,
  cryptor_manager::compute_wrapped_generation,
  frame_processors::{
    OutboundFrameProcessor, serialize_unencrypted_ranges, unencrypted_ranges_size,
  },
  hash_ratchet::HashRatchet,
  leb128::*,
  *,
};

#[cfg_attr(feature = "pyo3", pyclass(get_all, from_py_object))]
#[derive(Clone)]
pub struct EncryptionStats {
  /// Number of encryption successes
  pub successes: u64,
  /// Number of encryption failures
  pub failures: u64,
  /// Total encryption duration in microseconds
  pub duration: u64,
  /// Total amounts of encryption attempts
  pub attempts: u64,
  /// Maximum attempts reached at encryption
  pub max_attempts: u64,
  /// Number of encryptions that failed due to a missing key
  pub missing_keys: u64,
  /// Total amounts of packets that passed through
  pub passthroughs: u64,
}

pub struct Encryptor {
  ratchet: Option<HashRatchet>,
  cryptor: Option<AeadCipher>,
  current_key_generation: u32,
  truncated_nonce: u32,
  frame_processors: Vec<OutboundFrameProcessor>,
  pub stats: HashMap<MediaType, EncryptionStats>,
}

impl Encryptor {
  pub fn new() -> Self {
    let mut stats = HashMap::new();
    stats.insert(
      MediaType::AUDIO,
      EncryptionStats {
        successes: 0,
        failures: 0,
        duration: 0,
        attempts: 0,
        max_attempts: 0,
        missing_keys: 0,
        passthroughs: 0,
      },
    );
    stats.insert(
      MediaType::VIDEO,
      EncryptionStats {
        successes: 0,
        failures: 0,
        duration: 0,
        attempts: 0,
        max_attempts: 0,
        missing_keys: 0,
        passthroughs: 0,
      },
    );

    Self {
      ratchet: None,
      cryptor: None,
      current_key_generation: 0,
      truncated_nonce: 0,
      frame_processors: Vec::new(),
      stats,
    }
  }

  pub fn set_key_ratchet(&mut self, ratchet: HashRatchet) {
    self.ratchet = Some(ratchet);
    self.cryptor = None;
    self.current_key_generation = 0;
    self.truncated_nonce = 0;
  }

  /// Equivalent to `SetKeyRatchet(nullptr)`.
  pub fn clear_key_ratchet(&mut self) {
    self.ratchet = None;
    self.cryptor = None;
    self.current_key_generation = 0;
    self.truncated_nonce = 0;
  }

  pub fn has_key_ratchet(&self) -> bool {
    self.ratchet.is_some()
  }

  pub fn encrypt(
    &mut self,
    media_type: &MediaType,
    codec: Codec,
    frame: &[u8],
    encrypted_frame: &mut [u8],
  ) -> Result<usize, EncryptorEncryptError> {
    if self.ratchet.is_none() {
      warn!("encryption failed, no ratchet");
      let stats = self.stats.get_mut(media_type).unwrap();
      stats.failures += 1;
      stats.missing_keys += 1;
      return Err(EncryptorEncryptError::MissingKeyRatchet);
    }

    let start = Instant::now();

    let mut frame_processor = self.get_or_create_frame_processor();
    let result = self.encrypt_with_processor(
      media_type,
      codec,
      frame,
      encrypted_frame,
      &mut frame_processor,
    );
    self.return_frame_processor(frame_processor);

    let stats = self.stats.get_mut(media_type).unwrap();
    stats.duration += start.elapsed().as_micros() as u64;
    if result.is_ok() {
      stats.successes += 1;
    } else {
      stats.failures += 1;
    }

    result
  }

  fn encrypt_with_processor(
    &mut self,
    media_type: &MediaType,
    codec: Codec,
    frame: &[u8],
    encrypted_frame: &mut [u8],
    frame_processor: &mut OutboundFrameProcessor,
  ) -> Result<usize, EncryptorEncryptError> {
    frame_processor.process_frame(frame, codec);

    let unencrypted_ranges = &frame_processor.unencrypted_ranges;
    let ranges_size = unencrypted_ranges_size(unencrypted_ranges);

    let additional_data = &frame_processor.unencrypted_bytes;
    let plaintext_buffer = &frame_processor.encrypted_bytes;

    let frame_size =
      frame_processor.encrypted_bytes.len() + frame_processor.unencrypted_bytes.len();

    let mut nonce_buffer = [0u8; AES_GCM_128_NONCE_BYTES];

    const MAX_CIPHERTEXT_VALIDATION_RETRIES: usize = 10;

    // some codecs (e.g. H26X) have packetizers that cannot handle specific byte sequences
    // so we attempt up to MAX_CIPHERTEXT_VALIDATION_RETRIES to encrypt the frame
    // calling into codec utils to validate the ciphertext + supplemental section
    // and re-rolling the truncated nonce if it fails

    // the nonce increment will definitely change the ciphertext and the tag
    // incrementing the nonce will also change the appropriate bytes
    // in the tail end of the nonce
    // which can remove start codes from the last 1 or 2 bytes of the nonce
    // and the two bytes of the unencrypted header bytes
    for attempt in 1..=MAX_CIPHERTEXT_VALIDATION_RETRIES {
      let (curr_cryptor, truncated_nonce) = self.get_next_cryptor_and_nonce();

      if curr_cryptor.is_none() {
        self.stats.get_mut(media_type).unwrap().missing_keys += 1;
        return Err(EncryptorEncryptError::MissingCryptor);
      }

      let curr_cryptor = self.cryptor.as_mut().unwrap();

      nonce_buffer[AES_GCM_128_TRUNCATED_SYNC_NONCE_OFFSET
        ..AES_GCM_128_TRUNCATED_SYNC_NONCE_OFFSET + AES_GCM_128_TRUNCATED_SYNC_NONCE_BYTES]
        .copy_from_slice(&truncated_nonce.to_le_bytes());

      // ciphertext_bytes should be resized properly already
      if frame_processor.ciphertext_bytes.len() != plaintext_buffer.len() {
        warn!("encryption failed, plaintext mismatch (internal error!)");
        return Err(EncryptorEncryptError::EncryptionFailure);
      }
      frame_processor
        .ciphertext_bytes
        .copy_from_slice(plaintext_buffer);

      let encrypt_result = curr_cryptor.encrypt(
        frame_processor.ciphertext_bytes.as_mut_slice(),
        &nonce_buffer,
        additional_data,
      );

      let stats = self.stats.get_mut(media_type).unwrap();
      stats.attempts += 1;
      stats.max_attempts = stats.max_attempts.max(attempt as u64);

      let size = leb128_size(truncated_nonce as u64);
      let encrypted_frame_bytes =
        frame_size + AES_GCM_127_TRUNCATED_TAG_BYTES + size + ranges_size + 1 + MARKER_BYTES.len();
      if encrypted_frame_bytes > encrypted_frame.len() {
        warn!("encryption failed, encrypted frame buffer is too small");
        return Err(EncryptorEncryptError::EncryptionFailure);
      }

      if let Ok(tag) = encrypt_result {
        encrypted_frame[frame_size..frame_size + AES_GCM_127_TRUNCATED_TAG_BYTES]
          .copy_from_slice(&tag);
      } else {
        warn!("encryption failed, aead encryption failed");
        return Err(EncryptorEncryptError::EncryptionFailure);
      }

      let Ok(reconstructed_frame_size) = frame_processor.reconstruct_frame(encrypted_frame) else {
        warn!("encryption failed, frame is too small to contain the encrypted frame");
        return Err(EncryptorEncryptError::EncryptionFailure);
      };

      let (truncated_nonce_buffer, rest) =
        encrypted_frame[frame_size + AES_GCM_127_TRUNCATED_TAG_BYTES..].split_at_mut(size);
      let (unencrypted_ranges_buffer, rest) = rest.split_at_mut(ranges_size);
      let (supplemental_bytes_buffer, rest) = rest.split_at_mut(1);
      let (marker_bytes_buffer, _) = rest.split_at_mut(MARKER_BYTES.len());

      if write_leb128(truncated_nonce as u64, truncated_nonce_buffer) != size {
        warn!("encryption failed, write_leb128 failed");
        return Err(EncryptorEncryptError::EncryptionFailure);
      }

      if serialize_unencrypted_ranges(unencrypted_ranges, unencrypted_ranges_buffer) != ranges_size
      {
        warn!("encryption failed, serialize_unencrypted_ranges failed");
        return Err(EncryptorEncryptError::EncryptionFailure);
      }

      let supplemental_bytes_large = SUPPLEMENTAL_BYTES + size + ranges_size;
      if supplemental_bytes_large > u8::MAX as usize {
        warn!("encryption failed, supplemental_bytes_large check failed");
        return Err(EncryptorEncryptError::EncryptionFailure);
      }

      let supplemental_bytes = supplemental_bytes_large as u8;
      supplemental_bytes_buffer.copy_from_slice(&supplemental_bytes.to_le_bytes());

      marker_bytes_buffer.copy_from_slice(&MARKER_BYTES);

      let encrypted_frame_bytes = reconstructed_frame_size
        + AES_GCM_127_TRUNCATED_TAG_BYTES
        + size
        + ranges_size
        + 1
        + MARKER_BYTES.len();
      if encrypted_frame_bytes > encrypted_frame.len() {
        warn!("encryption failed, reconstructed encrypted frame exceeds buffer");
        return Err(EncryptorEncryptError::EncryptionFailure);
      }

      if validate_encrypted_frame(frame_processor, &encrypted_frame[..encrypted_frame_bytes]) {
        return Ok(encrypted_frame_bytes);
      }
    }

    warn!("encryption failed, reached max validation tries");
    Err(EncryptorEncryptError::TooManyAttempts)
  }

  /// Encrypts a frame into `encrypted_frame`, which is resized to fit the encrypted frame.
  pub fn encrypt_to_vec(
    &mut self,
    media_type: &MediaType,
    codec: Codec,
    frame: &[u8],
    encrypted_frame: &mut Vec<u8>,
  ) -> Result<(), EncryptorEncryptError> {
    encrypted_frame.resize(
      Self::get_max_ciphertext_byte_size(*media_type, frame.len()),
      0,
    );

    let result = self.encrypt(media_type, codec, frame, encrypted_frame);
    encrypted_frame.truncate(*result.as_ref().unwrap_or(&0));
    result.map(|_| ())
  }

  pub fn get_max_ciphertext_byte_size(_media_type: MediaType, frame_size: usize) -> usize {
    frame_size + SUPPLEMENTAL_BYTES + TRANSFORM_PADDING_BYTES
  }

  fn get_next_cryptor_and_nonce(&mut self) -> (Option<&AeadCipher>, u32) {
    if self.ratchet.is_none() {
      return (None, 0);
    }

    self.truncated_nonce += 1;
    let generation = compute_wrapped_generation(
      self.current_key_generation,
      self.truncated_nonce >> RATCHET_GENERATION_SHIFT_BITS,
    );

    if generation != self.current_key_generation || self.cryptor.is_none() {
      self.current_key_generation = generation;

      let result = self
        .ratchet
        .as_mut()
        .unwrap()
        .get(self.current_key_generation);
      match result {
        Ok((key, _)) => {
          let cipher = AeadCipher::new(key);
          self.cryptor = cipher.ok();
        }
        Err(err) => {
          warn!("Failed to get cryptor: {:?}", err);
          self.cryptor = None;
        }
      }
    }

    (self.cryptor.as_ref(), self.truncated_nonce)
  }

  fn get_or_create_frame_processor(&mut self) -> OutboundFrameProcessor {
    if self.frame_processors.is_empty() {
      return OutboundFrameProcessor::new();
    }
    self.frame_processors.pop().unwrap()
  }

  fn return_frame_processor(&mut self, frame_processor: OutboundFrameProcessor) {
    self.frame_processors.push(frame_processor);
  }
}
