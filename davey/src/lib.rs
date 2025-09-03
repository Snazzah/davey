#![deny(clippy::all)]
#![allow(clippy::upper_case_acronyms)]

mod aes_gcm;
mod cryptor;
mod displayable_code;
pub mod errors;
mod fingerprint;
mod session;
mod signing_key_pair;

pub use aes_gcm::*;
pub use cryptor::{
  Codec, DecryptionStats, EncryptionStats, MAX_FRAMES_PER_SECOND, MediaType, OPUS_SILENCE_PACKET,
};
pub use displayable_code::*;
pub use fingerprint::*;
pub use session::*;
pub use signing_key_pair::SigningKeyPair;
