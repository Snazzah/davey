use std::{
  cmp::min,
  collections::{HashMap, VecDeque},
  sync::Arc,
  time::{Duration, Instant},
};

use tracing::{debug, trace, warn};

use crate::errors::DecryptorDecryptError;

use super::{
  clock::Clock, cryptor_manager::CipherManager, frame_processors::InboundFrameProcessor,
  hash_ratchet::HashRatchet, *,
};

#[cfg_attr(feature = "pyo3", pyclass(get_all, from_py_object))]
#[derive(Clone)]
pub struct DecryptionStats {
  /// Number of decryption successes
  pub successes: u64,
  /// Number of decryption failures
  pub failures: u64,
  /// Total decryption duration in microseconds
  pub duration: u64,
  /// Total amounts of decryption attempts
  pub attempts: u64,
  /// Total amounts of packets that passed through
  pub passthroughs: u64,
}

pub struct Decryptor {
  clock: Arc<Clock>,
  cryptor_managers: VecDeque<CipherManager>,
  frame_processors: Vec<InboundFrameProcessor>,
  allow_passthrough_until: Option<Duration>, // None == TimePoint::max()
  pub stats: HashMap<MediaType, DecryptionStats>,
}

impl Decryptor {
  pub fn new() -> Self {
    Self::with_clock(Arc::new(Clock::new()))
  }

  pub(crate) fn with_clock(clock: Arc<Clock>) -> Self {
    let mut stats = HashMap::new();
    stats.insert(
      MediaType::AUDIO,
      DecryptionStats {
        successes: 0,
        failures: 0,
        duration: 0,
        attempts: 0,
        passthroughs: 0,
      },
    );
    stats.insert(
      MediaType::VIDEO,
      DecryptionStats {
        successes: 0,
        failures: 0,
        duration: 0,
        attempts: 0,
        passthroughs: 0,
      },
    );

    Self {
      clock,
      cryptor_managers: VecDeque::new(),
      frame_processors: Vec::new(),
      allow_passthrough_until: Some(Duration::new(0, 0)),
      stats,
    }
  }

  pub fn decrypt(
    &mut self,
    media_type: MediaType,
    encrypted_frame: &[u8],
    frame: &mut [u8],
  ) -> Result<usize, DecryptorDecryptError> {
    let start = Instant::now();

    // Skip decrypting for silence frames
    // This may change in the future, see: https://daveprotocol.com/#silence-packets
    if media_type == MediaType::AUDIO && encrypted_frame == OPUS_SILENCE_PACKET {
      let copy_size = min(frame.len(), encrypted_frame.len());
      frame[..copy_size].copy_from_slice(&encrypted_frame[..copy_size]);
      self.stats.get_mut(&media_type).unwrap().passthroughs += 1;
      return Ok(copy_size);
    }

    // Remove any expired cryptor manager
    self.cleanup_expired_cryptor_managers();

    // Process the incoming frame
    // This will check whether it looks like a valid encrypted frame
    // and if so it will parse it into its different components
    let mut local_frame = self.get_or_create_frame_processor();
    local_frame.parse_frame(encrypted_frame);

    // If the frame is not encrypted and we can pass it through, do it
    if !local_frame.encrypted && self.can_passthrough() {
      let copy_size = min(frame.len(), encrypted_frame.len());
      frame[..copy_size].copy_from_slice(&encrypted_frame[..copy_size]);
      let stats = self.stats.get_mut(&media_type).unwrap();
      stats.passthroughs += 1;
      self.return_frame_processor(local_frame);
      return Ok(copy_size);
    }

    let stats = self.stats.get_mut(&media_type).unwrap();
    // If the frame is not encrypted, and we can't pass it through, fail
    if !local_frame.encrypted {
      stats.failures += 1;
      self.return_frame_processor(local_frame);
      return Err(DecryptorDecryptError::UnencryptedWhenPassthroughDisabled);
    }

    let success = self
      .cryptor_managers
      .iter_mut()
      .rev()
      .any(|cryptor_manager| {
        stats.attempts += 1;

        Self::decrypt_impl(cryptor_manager, &mut local_frame)
      });

    let result = if success {
      stats.successes += 1;
      Ok(local_frame.reconstruct_frame(frame))
    } else {
      stats.failures += 1;
      Err(DecryptorDecryptError::NoValidCryptorFound {
        media_type,
        encrypted_size: encrypted_frame.len(),
        plaintext_size: frame.len(),
        manager_count: self.cryptor_managers.len(),
      })
    };

    let stats = self.stats.get_mut(&media_type).unwrap();
    stats.duration += start.elapsed().as_micros() as u64;

    // FIXME this technically should return when local_frame drops, but thats gonna be a bit annoying here
    self.return_frame_processor(local_frame);

    result
  }

  fn decrypt_impl(
    cipher_manager: &mut CipherManager,
    encrypted_frame: &mut InboundFrameProcessor,
  ) -> bool {
    // expand the truncated nonce to the full sized one needed for decryption
    let mut nonce_buffer = [0u8; AES_GCM_128_NONCE_BYTES];
    nonce_buffer[AES_GCM_128_TRUNCATED_SYNC_NONCE_OFFSET
      ..AES_GCM_128_TRUNCATED_SYNC_NONCE_OFFSET + AES_GCM_128_TRUNCATED_SYNC_NONCE_BYTES]
      .copy_from_slice(&encrypted_frame.truncated_nonce.to_le_bytes());

    let generation = cipher_manager
      .compute_wrapped_generation(encrypted_frame.truncated_nonce >> RATCHET_GENERATION_SHIFT_BITS);
    if !cipher_manager.can_process_nonce(generation, encrypted_frame.truncated_nonce) {
      trace!("decryption failed, cannot process nonce");
      return false;
    }

    let mut cipher = cipher_manager.get_cipher(generation);

    if cipher.is_none() {
      warn!("decryption failed, no cryptor found for generation {generation}");
      return false;
    }

    // plaintext should be resized properly already
    if encrypted_frame.plaintext.len() != encrypted_frame.ciphertext.len() {
      warn!("decryption failed, ciphertext mismatch (internal error!)");
      return false;
    }
    encrypted_frame
      .plaintext
      .copy_from_slice(&encrypted_frame.ciphertext);

    let result = cipher.as_mut().unwrap().decrypt(
      &mut encrypted_frame.plaintext,
      &nonce_buffer,
      &encrypted_frame.authenticated,
      &encrypted_frame.tag,
    );
    let success = result.is_ok();

    if success {
      cipher_manager.report_cipher_success(generation, encrypted_frame.truncated_nonce);
    }

    success
  }

  pub fn transition_to_key_ratchet(&mut self, ratchet: HashRatchet) {
    trace!("Transitioning to new key ratchet");

    // Remove expired cryptor managers first so a re-install of an expired key
    // domain is treated as a fresh install
    self.cleanup_expired_cryptor_managers();

    // Ignore a ratchet for a key domain that already has a live cryptor manager:
    // a sibling manager would give already-processed frames a fresh replay window.
    // A duplicate is not a real transition, so it must not extend expiries either.
    if self
      .cryptor_managers
      .iter()
      .any(|cryptor_manager| cryptor_manager.domain_identity() == ratchet.domain_identity())
    {
      debug!("Ignoring key ratchet for already installed key domain");
      return;
    }

    self.update_cryptor_manager_expiry(RATCHET_EXPIRY);
    self
      .cryptor_managers
      .push_back(CipherManager::new(self.clock.clone(), ratchet));
  }

  /// Equivalent to `TransitionToKeyRatchet(nullptr)`.
  pub fn expire_key_ratchets(&mut self) {
    trace!("Expiring key ratchets");
    self.cleanup_expired_cryptor_managers();
    self.update_cryptor_manager_expiry(RATCHET_EXPIRY);
  }

  pub fn transition_to_passthrough_mode(&mut self, mode: bool, transition_expiry: usize) {
    if mode {
      self.allow_passthrough_until = None;
    } else {
      let new_expiry = self.clock.elapsed() + Duration::from_secs(transition_expiry as u64);
      self.allow_passthrough_until = Some(
        self
          .allow_passthrough_until
          .map(|prev_expiry| min(prev_expiry, new_expiry))
          .unwrap_or(new_expiry),
      );
    }
  }

  pub fn can_passthrough(&self) -> bool {
    self.allow_passthrough_until.is_none()
      || self.allow_passthrough_until.unwrap() > self.clock.elapsed()
  }

  pub fn get_max_plaintext_byte_size(_media_type: MediaType, encrypted_frame_size: usize) -> usize {
    encrypted_frame_size
  }

  fn update_cryptor_manager_expiry(&mut self, expiry: Duration) {
    let max_expiry_time = self.clock.elapsed() + expiry;
    for cryptor_manager in self.cryptor_managers.iter_mut() {
      cryptor_manager.update_expiry(max_expiry_time);
    }
  }

  fn cleanup_expired_cryptor_managers(&mut self) {
    while let Some(front) = self.cryptor_managers.front() {
      if !front.is_expired() {
        break;
      }
      self.cryptor_managers.pop_front();
    }
  }

  fn get_or_create_frame_processor(&mut self) -> InboundFrameProcessor {
    if self.frame_processors.is_empty() {
      return InboundFrameProcessor::new();
    }
    self.frame_processors.pop().unwrap()
  }

  fn return_frame_processor(&mut self, frame_processor: InboundFrameProcessor) {
    self.frame_processors.push(frame_processor);
  }
}
