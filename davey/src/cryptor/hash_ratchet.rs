use std::collections::HashMap;
use tracing::{debug, trace};

use crate::errors::{GetKeyError, InvalidLength};

use super::mlspp_crypto::derive_tree_secret;

/// An implementation of libdave's HashRatchet.
pub struct HashRatchet {
  next_secret: Vec<u8>,
  next_generation: u32,
  cache: HashMap<u32, (Vec<u8>, Vec<u8>)>,
  domain_identity: Vec<u8>,
}

impl HashRatchet {
  pub fn new(secret: Vec<u8>) -> Self {
    trace!("Creating hash ratchet with secret: {:x?}", secret);
    Self {
      next_generation: 0,
      domain_identity: secret.clone(),
      next_secret: secret,
      cache: HashMap::new(),
    }
  }

  /// The base secret is derived per (epoch, user), so it identifies the key domain
  pub fn domain_identity(&self) -> &[u8] {
    &self.domain_identity
  }

  // https://www.rfc-editor.org/rfc/rfc9420.html#section-9.1-11.1
  fn next(&mut self) -> Result<(), InvalidLength> {
    let generation = self.next_generation;
    let key = derive_tree_secret(
      &self.next_secret,
      "key",
      generation,
      // RATCHET_CIPHERSUITE.aead_key_length()
      16,
    )?;
    let nonce = derive_tree_secret(
      &self.next_secret,
      "nonce",
      generation,
      // RATCHET_CIPHERSUITE.aead_nonce_length()
      12,
    )?;
    self.next_secret = derive_tree_secret(
      &self.next_secret,
      "secret",
      generation,
      // RATCHET_CIPHERSUITE.hash_length()
      32,
    )?;
    self.next_generation = self.next_generation.wrapping_add(1);
    self.cache.insert(generation, (key, nonce));
    Ok(())
  }

  pub fn get(&mut self, generation: u32) -> Result<(&[u8], &[u8]), GetKeyError> {
    if self.cache.contains_key(&generation) {
      let key = self.cache.get(&generation).unwrap();
      return Ok((&key.0, &key.1));
    }

    if self.next_generation > generation {
      return Err(GetKeyError::KeyExpired);
    }

    debug!(
      "Getting generation {} (from next gen {})",
      generation, self.next_generation
    );
    while self.next_generation <= generation {
      self
        .next()
        .map_err(|err| GetKeyError::NextGenerationFailed(self.next_generation, err))?;
    }

    let key = self.cache.get(&generation).unwrap();
    Ok((&key.0, &key.1))
  }

  pub fn erase(&mut self, generation: u32) {
    self.cache.remove(&generation);
  }
}
