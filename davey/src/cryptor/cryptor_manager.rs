#![allow(clippy::map_entry)]
use std::{
  cmp::max,
  collections::{HashMap, VecDeque},
  sync::Arc,
  time::{Duration, Instant},
};
use tracing::{debug, trace, warn};

use crate::errors::ExpiringCipherError;

use super::{CIPHER_EXPIRY, MAX_MISSING_NONCES};

use super::{aead_cipher::AeadCipher, hash_ratchet::HashRatchet, *};

pub fn compute_wrapped_generation(oldest: u32, generation: u32) -> u32 {
  // Assume generation is greater than or equal to oldest, this may be wrong in a few cases but
  // will be caught by the max generation gap check.
  let remainder = oldest % GENERATION_WRAP;
  let mut extra: u32 = 0;
  if generation < remainder {
    extra = 1;
  }
  let factor = oldest / GENERATION_WRAP + extra;
  factor * GENERATION_WRAP + generation
}

fn compute_wrapped_big_nonce(generation: u32, nonce: u32) -> u64 {
  // Remove the generation bits from the nonce
  let masked_nonce = (nonce as u64) & ((1 << RATCHET_GENERATION_SHIFT_BITS) - 1);
  // Add the wrapped generation bits back in
  ((generation as u64) << RATCHET_GENERATION_SHIFT_BITS) | masked_nonce
}

struct ExpiringCipher {
  cipher: AeadCipher,
  expiry: Option<Duration>,
}

pub struct CipherManager {
  clock: Arc<Instant>,
  key_ratchet: HashRatchet,
  cryptor_generations: HashMap<u32, ExpiringCipher>,
  ratchet_creation: Duration,
  ratchet_expiry: Option<Duration>,
  oldest_generation: u32,
  newest_generation: u32,
  newest_processed_nonce: Option<u64>,
  missing_nonces: VecDeque<u64>,
}

impl CipherManager {
  pub fn new(clock: Arc<Instant>, key_ratchet: HashRatchet) -> Self {
    let ratchet_creation: Duration = clock.as_ref().elapsed();
    Self {
      clock,
      key_ratchet,
      cryptor_generations: HashMap::new(),
      ratchet_creation,
      ratchet_expiry: None,
      oldest_generation: 0,
      newest_generation: 0,
      newest_processed_nonce: None,
      missing_nonces: VecDeque::new(),
    }
  }

  pub fn can_process_nonce(&self, generation: u32, nonce: u32) -> bool {
    if self.newest_processed_nonce.is_none() {
      return true;
    }

    let wrapped_big_nonce = compute_wrapped_big_nonce(generation, nonce);
    wrapped_big_nonce > self.newest_processed_nonce.unwrap()
      || self.missing_nonces.contains(&wrapped_big_nonce)
  }

  pub fn get_cipher(&mut self, generation: u32) -> Option<&mut AeadCipher> {
    self.cleanup_expired_ciphers();

    if generation < self.oldest_generation {
      trace!(
        "Received frame with old generation: {:?}, oldest generation: {:?}",
        generation, self.oldest_generation
      );
      return None;
    }

    if generation > self.newest_generation + MAX_GENERATION_GAP {
      trace!(
        "Received frame with future generation: {:?}, newest generation: {:?}",
        generation, self.newest_generation
      );
      return None;
    }

    let ratchet_lifetime_sec = (self.clock.elapsed() - self.ratchet_creation).as_secs();
    let max_lifetime_frames = MAX_FRAMES_PER_SECOND * ratchet_lifetime_sec;
    let max_lifetime_generations = max_lifetime_frames >> RATCHET_GENERATION_SHIFT_BITS;
    if generation > max_lifetime_generations as u32 {
      debug!(
        "Received frame with generation {:?} beyond ratchet max lifetime generations: {:?}, ratchet lifetime: {:?}",
        generation, max_lifetime_generations, ratchet_lifetime_sec
      );
      return None;
    }

    if !self.cryptor_generations.contains_key(&generation) {
      let ec_result = self.make_expiring_cipher(generation);
      if ec_result.is_err() {
        let err = ec_result.err().unwrap();
        warn!("Error while making expiring cipher: {err}");
        return None;
      }
      self
        .cryptor_generations
        .insert(generation, ec_result.unwrap());
    }

    Some(
      &mut self
        .cryptor_generations
        .get_mut(&generation)
        .unwrap()
        .cipher,
    )
  }

  pub fn report_cipher_success(&mut self, generation: u32, nonce: u32) {
    let wrapped_big_nonce = compute_wrapped_big_nonce(generation, nonce);

    // Add any missing nonces to the queue
    if self.newest_processed_nonce.is_none() {
      self.newest_processed_nonce = Some(wrapped_big_nonce);
    } else if wrapped_big_nonce > self.newest_processed_nonce.unwrap() {
      let oldest_missing_nonce = wrapped_big_nonce.saturating_sub(MAX_MISSING_NONCES);

      while !self.missing_nonces.is_empty()
        && self.missing_nonces.front().unwrap() < &oldest_missing_nonce
      {
        self.missing_nonces.pop_front();
      }

      // If we're missing a lot, we don't want to add everything since newestProcessedNonce_
      let missing_range_start = max(
        oldest_missing_nonce,
        self.newest_processed_nonce.unwrap() + 1,
      );
      for i in missing_range_start..wrapped_big_nonce {
        self.missing_nonces.push_back(i);
      }

      // Update the newest processed nonce
      self.newest_processed_nonce = Some(wrapped_big_nonce);
    } else if let Some(index) = self
      .missing_nonces
      .iter()
      .position(|&x| x == wrapped_big_nonce)
    {
      self.missing_nonces.remove(index);
    }

    if generation <= self.newest_generation || !self.cryptor_generations.contains_key(&generation) {
      return;
    }

    trace!("Reporting cryptor success, generation: {generation}");
    self.newest_generation = generation;

    // Update the expiry time for all old cryptors
    let expiry_time = self.clock.elapsed() + CIPHER_EXPIRY;
    for (cryptor_generation, cryptor) in self.cryptor_generations.iter_mut() {
      if cryptor_generation < &self.newest_generation {
        trace!("Updating expiry for cryptor, generation: {cryptor_generation}");
        cryptor.expiry = Some(expiry_time)
      }
    }
  }

  pub fn compute_wrapped_generation(&self, generation: u32) -> u32 {
    compute_wrapped_generation(self.oldest_generation, generation)
  }

  fn make_expiring_cipher(
    &mut self,
    generation: u32,
  ) -> Result<ExpiringCipher, ExpiringCipherError> {
    // Get the new key from the ratchet
    let (key, _nonce) = self.key_ratchet.get(generation)?;

    // If we got frames out of order, we might have to create a cryptor for an old generation
    // In that case, create it with a non-infinite expiry time as we have already transitioned
    // to a newer generation
    let expiry_time: Option<Duration> = {
      if generation < self.newest_generation {
        debug!("Creating cryptor for old generation {:?}", generation);
        Some(self.clock.elapsed() + CIPHER_EXPIRY)
      } else {
        debug!("Creating cryptor for new generation {:?}", generation);
        None
      }
    };

    Ok(ExpiringCipher {
      cipher: AeadCipher::new(key)?,
      expiry: expiry_time,
    })
  }

  fn cleanup_expired_ciphers(&mut self) {
    self.cryptor_generations.retain(|&generation, ec| {
      let expired = if let Some(expiry) = ec.expiry {
        expiry < self.clock.elapsed()
      } else {
        false
      };
      if expired {
        trace!("Removing expired cryptor, generation: {generation}");
      }
      !expired
    });

    while self.oldest_generation < self.newest_generation
      && !self
        .cryptor_generations
        .contains_key(&self.oldest_generation)
    {
      trace!(
        "Deleting key for old generation: {:?}",
        self.oldest_generation
      );
      self.key_ratchet.erase(self.oldest_generation);
      self.oldest_generation += 1;
    }
  }

  pub fn update_expiry(&mut self, expiry: Duration) {
    self.ratchet_expiry = Some(expiry);
  }

  pub fn is_expired(&self) -> bool {
    if self.ratchet_expiry.is_none() {
      return false;
    }

    self.clock.elapsed() > self.ratchet_expiry.unwrap()
  }
}
