#[cfg(feature = "napi")]
use napi_derive::napi;
#[cfg(feature = "pyo3")]
use pyo3::prelude::*;
use std::time::Duration;

pub const OPUS_SILENCE_PACKET: [u8; 3] = [0xF8, 0xFF, 0xFE];

/** Magic marker ID */
pub const MARKER_BYTES: [u8; 2] = [0xFA, 0xFA];

/** Layout constants */
pub const AES_GCM_128_KEY_BYTES: usize = 16;
pub const AES_GCM_128_NONCE_BYTES: usize = 12;
pub const AES_GCM_128_TRUNCATED_SYNC_NONCE_BYTES: usize = 4;
pub const AES_GCM_128_TRUNCATED_SYNC_NONCE_OFFSET: usize =
  AES_GCM_128_NONCE_BYTES - AES_GCM_128_TRUNCATED_SYNC_NONCE_BYTES;
pub const RATCHET_GENERATION_BYTES: usize = 1;
pub const AES_GCM_127_TRUNCATED_TAG_BYTES: usize = 8;
pub const RATCHET_GENERATION_SHIFT_BITS: usize =
  8 * (AES_GCM_128_TRUNCATED_SYNC_NONCE_BYTES - RATCHET_GENERATION_BYTES);
pub const SUPPLEMENTAL_BYTES: usize = AES_GCM_127_TRUNCATED_TAG_BYTES + 1 + 2;
pub const TRANSFORM_PADDING_BYTES: usize = 64;

/** Timing constants */
pub const CIPHER_EXPIRY: Duration = Duration::new(10, 0);
pub const RATCHET_EXPIRY: Duration = Duration::new(10, 0);

/** Behavior constants */
pub const MAX_GENERATION_GAP: u32 = 250;
pub const MAX_MISSING_NONCES: u64 = 1000;
pub const GENERATION_WRAP: u32 = 1 << (8 * RATCHET_GENERATION_BYTES);
pub const MAX_FRAMES_PER_SECOND: u64 = 50 + 2 * 60; // 50 audio frames + 2 * 60fps video streams

#[cfg_attr(feature = "napi", napi)]
#[cfg_attr(feature = "pyo3", pyclass(eq, eq_int, rename_all = "snake_case"))]
#[derive(Debug, Clone, Copy, Hash, PartialEq, Eq)]
pub enum MediaType {
  AUDIO = 0,
  VIDEO = 1,
}

#[cfg_attr(feature = "napi", napi)]
#[cfg_attr(feature = "pyo3", pyclass(eq, eq_int, rename_all = "snake_case"))]
#[derive(Debug, Clone, Copy, PartialEq)]
pub enum Codec {
  UNKNOWN = 0,
  OPUS = 1,
  VP8 = 2,
  VP9 = 3,
  H264 = 4,
  H265 = 5,
  AV1 = 6,
}

pub(crate) mod aead_cipher;
pub(crate) mod codec_utils;
pub(crate) mod cryptor_manager;
pub(crate) mod decryptor;
pub(crate) mod encryptor;
pub(crate) mod frame_processors;
pub(crate) mod hash_ratchet;
pub(crate) mod leb128;
pub(crate) mod mlspp_crypto;

pub use decryptor::DecryptionStats;
pub use encryptor::EncryptionStats;
