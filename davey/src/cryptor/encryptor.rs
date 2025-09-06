#[cfg(feature = "napi")]
use napi_derive::napi;
#[cfg(feature = "pyo3")]
use pyo3::prelude::*;
use std::{collections::HashMap, time::Instant};

use tracing::warn;

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

#[cfg_attr(feature = "napi", napi(object))]
#[cfg_attr(feature = "pyo3", pyclass(get_all))]
#[derive(Clone)]
pub struct EncryptionStats {
  /// Number of encryption successes
  pub successes: u32,
  /// Number of encryption failures
  pub failures: u32,
  /// Total encryption duration in microseconds
  pub duration: u32,
  /// Total amounts of encryption attempts
  pub attempts: u32,
  /// Maximum attempts reached at encryption
  pub max_attempts: u32,
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

  // TODO use results to propogate errors up and return properly
  pub fn encrypt(
    &mut self,
    media_type: &MediaType,
    codec: Codec,
    frame: &[u8],
    encrypted_frame: &mut [u8],
    bytes_written: &mut usize,
  ) -> bool {
    if *media_type != MediaType::AUDIO && *media_type != MediaType::VIDEO {
      warn!("encryption failed, invalid media type {:?}", media_type);
      return false;
    }

    let stats = self.stats.get_mut(media_type).unwrap();

    if self.ratchet.is_none() {
      warn!("encryption failed, no ratchet");
      stats.failures += 1;
      return false;
    }

    let start = Instant::now();
    let mut success = true;

    let mut frame_processor = self.get_or_create_frame_processor();

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
        warn!("encryption failed, no cryptor");
        success = false;
        break;
      }

      let curr_cryptor = self.cryptor.as_mut().unwrap();

      nonce_buffer[AES_GCM_128_TRUNCATED_SYNC_NONCE_OFFSET
        ..AES_GCM_128_TRUNCATED_SYNC_NONCE_OFFSET + AES_GCM_128_TRUNCATED_SYNC_NONCE_BYTES]
        .copy_from_slice(&truncated_nonce.to_le_bytes());

      // ciphertext_bytes should be resized properly already
      if frame_processor.ciphertext_bytes.len() != plaintext_buffer.len() {
        warn!("encryption failed, plaintext mismatch (internal error!)");
        success = false;
        break;
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
      stats.max_attempts = stats.max_attempts.max(attempt as u32);

      if let Ok(tag) = encrypt_result {
        encrypted_frame[frame_size..frame_size + AES_GCM_127_TRUNCATED_TAG_BYTES]
          .copy_from_slice(&tag);
      } else {
        warn!("encryption failed, aead encryption failed");
        success = false;
        break;
      }

      let Ok(reconstructed_frame_size) = frame_processor.reconstruct_frame(encrypted_frame) else {
        warn!("encryption failed, frame is too small to contain the encrypted frame");
        success = false;
        break;
      };

      let size = leb128_size(truncated_nonce as u64);

      let (truncated_nonce_buffer, rest) =
        encrypted_frame[frame_size + AES_GCM_127_TRUNCATED_TAG_BYTES..].split_at_mut(size);
      let (unencrypted_ranges_buffer, rest) = rest.split_at_mut(ranges_size as usize);
      let (supplemental_bytes_buffer, rest) = rest.split_at_mut(1);
      let (marker_bytes_buffer, _) = rest.split_at_mut(MARKER_BYTES.len());

      if write_leb128(truncated_nonce as u64, truncated_nonce_buffer) != size {
        warn!("encryption failed, write_leb128 failed");
        success = false;
        break;
      }

      if serialize_unencrypted_ranges(unencrypted_ranges, unencrypted_ranges_buffer) != ranges_size
      {
        warn!("encryption failed, serialize_unencrypted_ranges failed");
        success = false;
        break;
      }

      let supplemental_bytes_large = SUPPLEMENTAL_BYTES + size + ranges_size as usize;
      if supplemental_bytes_large > u8::MAX as usize {
        warn!("encryption failed, supplemental_bytes_large check failed");
        success = false;
        break;
      }

      let supplemental_bytes = supplemental_bytes_large as u8;
      supplemental_bytes_buffer.copy_from_slice(&supplemental_bytes.to_le_bytes());

      marker_bytes_buffer.copy_from_slice(&MARKER_BYTES);

      let encrypted_frame_bytes = reconstructed_frame_size
        + AES_GCM_127_TRUNCATED_TAG_BYTES
        + size
        + ranges_size as usize
        + 1
        + MARKER_BYTES.len();

      if validate_encrypted_frame(&frame_processor, &encrypted_frame[..encrypted_frame_bytes]) {
        *bytes_written = encrypted_frame_bytes;
        break;
      } else if attempt >= MAX_CIPHERTEXT_VALIDATION_RETRIES {
        warn!("encryption failed, reached max validation tries");
        success = false;
        break;
      }
    }

    let stats = self.stats.get_mut(media_type).unwrap();
    stats.duration += start.elapsed().as_micros() as u32;
    if success {
      stats.successes += 1;
    } else {
      stats.failures += 1;
    }

    // FIXME this technically should return when frame_processor drops, but thats gonna be a bit annoying here
    self.return_frame_processor(frame_processor);

    success
  }

  pub fn get_max_ciphertext_byte_size(_media_type: &MediaType, frame_size: usize) -> usize {
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
