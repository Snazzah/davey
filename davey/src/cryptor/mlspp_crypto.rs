//! A module that has converted MLS++'s functions needed for [Sender Key Derivation][1].
//!
//! A problem I ran into is that when trying to use OpenMLS' [`openmls::tree::sender_ratchet::RatchetSecret`] for [Sender Key Derivation][1]
//! is that when trying to derive tree secrets, the library gives a `CryptoError::HkdfOutputLengthInvalid` due to
//! the secret length being 16 bytes, while the requested size is different.
//!
//! In OpenMLS's implementation, these lengths are more harshly enforced, while in MLS++, they are resized to match.
//! So this file is for running over necessary functions that depend on `derive_tree_secret`. Don't like how long that took to figure out.
//!
//! [1]: https://daveprotocol.com/#sender-key-derivation

use hmac::{Hmac, Mac};
use openmls::prelude::{
  TlsSerialize, TlsSize, VLBytes,
  tls_codec::{self, Serialize},
};
use sha2::Sha256;
use tracing::{debug, trace};

use crate::errors::InvalidLength;

#[derive(Debug, TlsSerialize, TlsSize)]
pub struct KdfLabel {
  length: u16,
  label: VLBytes,
  context: VLBytes,
}

// https://github.com/cisco/mlspp/blob/f7924fc87f77f60a0ea8488615c9fb46c7b386e6/lib/hpke/src/hkdf.cpp#L63
fn hkdf_expand(prk: &[u8], info: &[u8], size: usize) -> Result<Vec<u8>, InvalidLength> {
  let mut okm: Vec<u8> = vec![];
  let mut i: u8 = 0;
  let mut ti: Vec<u8> = vec![];
  while okm.len() < size {
    i += 1;
    let mut block: Vec<u8> = vec![];
    block.append(&mut ti);
    block.extend_from_slice(info);
    block.push(i);

    let mut hmac = Hmac::<Sha256>::new_from_slice(prk).map_err(|_| InvalidLength)?;
    hmac.update(&block);
    ti = hmac.finalize().into_bytes().to_vec();

    okm.extend_from_slice(&ti);
  }

  okm.resize(size, 0);
  Ok(okm)
}

// https://github.com/cisco/mlspp/blob/f7924fc87f77f60a0ea8488615c9fb46c7b386e6/src/crypto.cpp#L177
fn expand_with_label(
  secret: &[u8],
  label: &str,
  context: &[u8],
  length: usize,
) -> Result<Vec<u8>, InvalidLength> {
  let mls_label = format!("MLS 1.0 {label}");
  trace!(
    "KDF expand with label \"{}\" with context {:x?}",
    &mls_label, context
  );
  let kdf_label = KdfLabel {
    length: length as u16,
    label: mls_label.as_bytes().into(),
    context: context.into(),
  };
  trace!("  label: {:x?}", kdf_label);
  let info = kdf_label
    .tls_serialize_detached()
    .expect("failed to serialize kdf label");
  trace!("  serialized info: {:x?}", info);
  trace!("  secret: {:x?}", secret);
  hkdf_expand(secret, &info, length)
}

// https://github.com/cisco/mlspp/blob/f7924fc87f77f60a0ea8488615c9fb46c7b386e6/src/crypto.cpp#L195
pub fn derive_tree_secret(
  secret: &[u8],
  label: &str,
  generation: u32,
  length: usize,
) -> Result<Vec<u8>, InvalidLength> {
  debug!(
    "Derive tree secret with label \"{}\" in generation {} of length {}",
    label, generation, length
  );
  trace!("Input secret {:x?}", secret);
  let new_secret = expand_with_label(secret, label, &generation.to_be_bytes(), length)?;
  trace!("Derived secret {:x?}", new_secret);
  Ok(new_secret)
}
