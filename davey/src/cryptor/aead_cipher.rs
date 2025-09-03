use crate::aes_gcm::{AesGcm, KeyInit, aead::AeadMutInPlace, aes::Aes128};
use sha2::digest::{
  InvalidLength,
  consts::{U8, U12},
};

type Aes128GcmModified = AesGcm<Aes128, U12, U8>;

pub struct AeadCipher {
  key: Aes128GcmModified,
}

impl AeadCipher {
  pub fn new(key: &[u8]) -> Result<Self, InvalidLength> {
    Ok(Self {
      key: Aes128GcmModified::new_from_slice(key)?,
    })
  }

  pub fn encrypt(
    &mut self,
    buffer: &mut [u8],
    nonce: &[u8],
    aad: &[u8],
  ) -> crate::aes_gcm::aead::Result<[u8; 8]> {
    self
      .key
      .encrypt_in_place_detached(nonce.into(), aad, buffer)
      .map(|tag| tag.into())
  }

  pub fn decrypt(
    &mut self,
    buffer: &mut [u8],
    nonce: &[u8],
    aad: &[u8],
    tag: &[u8],
  ) -> crate::aes_gcm::aead::Result<()> {
    self
      .key
      .decrypt_in_place_detached(nonce.into(), aad, buffer, tag.into())
  }
}
