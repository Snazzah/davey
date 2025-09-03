use std::num::NonZeroU16;

use crate::{AsyncPairwiseFingerprintSession, AsyncSessionVerificationCode, SigningKeyPair};
use napi::bindgen_prelude::{AsyncTask, Buffer};

pub use davey::{
  Codec, DecryptionStats, EncryptionStats, MediaType, ProposalsOperationType, SessionStatus,
  DAVE_PROTOCOL_VERSION,
};

#[napi(js_name = "DAVESession")]
pub struct DaveSession {
  inner: Box<davey::DaveSession>,
}

#[napi(object)]
pub struct ProposalsResult {
  pub commit: Option<Buffer>,
  pub welcome: Option<Buffer>,
}

#[napi]
impl DaveSession {
  /// @param protocolVersion The protocol version to use.
  /// @param userId The user ID of the session.
  /// @param channelId The channel ID of the session.
  /// @param keyPair The key pair to use for this session. Will generate a new one if not specified.
  #[napi(constructor)]
  pub fn new(
    protocol_version: u16,
    user_id: String,
    channel_id: String,
    key_pair: Option<SigningKeyPair>,
  ) -> napi::Result<Self> {
    let (protocol_version, uid, cid, signing_key_pair) =
      Self::common_init(protocol_version, user_id, channel_id, key_pair)?;

    let session = davey::DaveSession::new(protocol_version, uid, cid, signing_key_pair.as_ref())
      .map_err(|err| napi_error!("Failed to initialize session: {err:?}"))?;

    Ok(Self {
      inner: Box::new(session),
    })
  }

  fn common_init(
    protocol_version: u16,
    user_id: String,
    channel_id: String,
    key_pair: Option<SigningKeyPair>,
  ) -> napi::Result<(NonZeroU16, u64, u64, Option<davey::SigningKeyPair>)> {
    let protocol_version = NonZeroU16::new(protocol_version)
      .ok_or(napi_invalid_arg_error!("Unsupported protocol version"))?;
    let uid = user_id
      .parse::<u64>()
      .map_err(|_| napi_invalid_arg_error!("Invalid user id"))?;
    let cid = channel_id
      .parse::<u64>()
      .map_err(|_| napi_invalid_arg_error!("Invalid channel id"))?;

    let key_pair = key_pair.map(|kp| davey::SigningKeyPair {
      private: kp.private.to_vec(),
      public: kp.public.to_vec(),
    });

    Ok((protocol_version, uid, cid, key_pair))
  }

  /// Resets and re-initializes the session.
  /// @param protocolVersion The protocol version to use.
  /// @param userId The user ID of the session.
  /// @param channelId The channel ID of the session.
  /// @param keyPair The key pair to use for this session. Will generate a new one if not specified.
  #[napi]
  pub fn reinit(
    &mut self,
    protocol_version: u16,
    user_id: String,
    channel_id: String,
    key_pair: Option<SigningKeyPair>,
  ) -> napi::Result<()> {
    let (protocol_version, uid, cid, signing_key_pair) =
      Self::common_init(protocol_version, user_id, channel_id, key_pair)?;

    self
      .inner
      .reinit(protocol_version, uid, cid, signing_key_pair.as_ref())
      .map_err(|err| napi_error!("Failed to re-initialize session: {err:?}"))?;

    Ok(())
  }

  /// Resets the session by deleting the group and clearing the storage.
  /// If you want to re-initialize the session, use {@link reinit}.
  #[napi]
  pub fn reset(&mut self) -> napi::Result<()> {
    self
      .inner
      .reset()
      .map_err(|err| napi_error!("Failed to reset session: {err:?}"))?;

    Ok(())
  }

  /// The DAVE protocol version used for this session.
  #[napi(getter)]
  pub fn protocol_version(&self) -> u16 {
    self.inner.protocol_version().get()
  }

  /// The user ID for this session.
  #[napi(getter)]
  pub fn user_id(&self) -> String {
    self.inner.user_id().to_string()
  }

  /// The channel ID (group ID in MLS standards) for this session.
  #[napi(getter)]
  pub fn channel_id(&self) -> String {
    self.inner.channel_id().to_string()
  }

  /// The epoch for this session, `undefined` if there is no group yet.
  #[napi(getter)]
  pub fn epoch(&self) -> Option<u64> {
    self.inner.epoch().map(|e| e.as_u64())
  }

  /// Your own leaf index for this session, `undefined` if there is no group yet.
  #[napi(getter)]
  pub fn own_leaf_index(&self) -> Option<u32> {
    self.inner.own_leaf_index().map(|e| e.u32())
  }

  /// The ciphersuite being used in this session.
  #[napi(getter)]
  pub fn ciphersuite(&self) -> u16 {
    self.inner.ciphersuite() as u16
  }

  /// Session status as a number (matches the JS enum in the old bindings).
  #[napi(getter)]
  pub fn status(&self) -> SessionStatus {
    self.inner.status()
  }

  /// Whether the session is ready to encrypt/decrypt.
  #[napi(getter)]
  pub fn ready(&self) -> bool {
    self.inner.is_ready()
  }

  /// Get the epoch authenticator of this session's group.
  #[napi]
  pub fn get_epoch_authenticator(&self) -> Option<Buffer> {
    self
      .inner
      .get_epoch_authenticator()
      .map(|ea| Buffer::from(ea.as_slice()))
  }

  /// Get the voice privacy code of this session's group.
  /// The result of this is created and cached each time a new transition is executed.
  /// This is the equivalent of `generateDisplayableCode(epochAuthenticator, 30, 5)`.
  /// @returns The current voice privacy code, or an empty string if the session is not active.
  /// @see https://daveprotocol.com/#displayable-codes
  #[napi(getter)]
  pub fn voice_privacy_code(&self) -> String {
    self
      .inner
      .voice_privacy_code()
      .map(|vpc| vpc.to_string())
      .unwrap_or("".to_string())
  }

  /// Set the external sender this session will recieve from.
  /// @param externalSenderData The serialized external sender data.
  /// @throws Will throw if the external sender is invalid, or if the group has been established already.
  /// @see https://daveprotocol.com/#dave_mls_external_sender_package-25
  #[napi]
  pub fn set_external_sender(&mut self, external_sender_data: Buffer) -> napi::Result<()> {
    self
      .inner
      .set_external_sender(&external_sender_data)
      .map_err(|err| napi_error!("Failed to set external sender: {err:?}"))?;

    Ok(())
  }

  /// Create, store, and return the serialized key package buffer.
  /// Key packages are not meant to be reused, and will be recreated on each call of this function.
  #[napi]
  pub fn get_serialized_key_package(&mut self) -> napi::Result<Buffer> {
    let key_package = self
      .inner
      .create_key_package()
      .map_err(|err| napi_error!("Failed to create key package: {err:?}"))?;

    Ok(Buffer::from(key_package))
  }

  /// Process proposals from an opcode 27 payload.
  /// @param operationType The operation type of the proposals.
  /// @param proposals The vector of proposals or proposal refs of the payload. (depending on operation type)
  /// @param recognizedUserIds The recognized set of user IDs gathered from the voice gateway. Recommended to set so that incoming users are checked against.
  /// @returns A commit (if there were queued proposals) and a welcome (if a member was added) that should be used to send an [opcode 28: dave_mls_commit_welcome](https://daveprotocol.com/#dave_mls_commit_welcome-28) ONLY if a commit was returned.
  /// @see https://daveprotocol.com/#dave_mls_proposals-27
  #[napi]
  pub fn process_proposals(
    &mut self,
    operation_type: ProposalsOperationType,
    proposals: Buffer,
    recognized_user_ids: Option<Vec<String>>,
  ) -> napi::Result<ProposalsResult> {
    let uids_vec = if let Some(ids) = recognized_user_ids {
      let mut parsed = Vec::with_capacity(ids.len());
      for s in ids {
        let id = s
          .parse::<u64>()
          .map_err(|_| napi_invalid_arg_error!("Invalid recognized user id"))?;
        parsed.push(id);
      }
      Some(parsed)
    } else {
      None
    };
    let uids: Option<&[u64]> = uids_vec.as_deref();
    let result = self
      .inner
      .process_proposals(operation_type, &proposals, uids)
      .map_err(|err| napi_error!("Failed to process proposals: {err:?}"))?;

    Ok(
      result
        .map(|cw| ProposalsResult {
          commit: Some(Buffer::from(cw.commit)),
          welcome: cw.welcome.map(Buffer::from),
        })
        .or_else(|| {
          Some(ProposalsResult {
            commit: None,
            welcome: None,
          })
        })
        .unwrap(),
    )
  }

  /// Process a welcome message.
  /// @param welcome The welcome message to process.
  /// @throws Will throw an error if the welcome is invalid. Send an [opcode 31: dave_mls_invalid_commit_welcome](https://daveprotocol.com/#dave_mls_invalid_commit_welcome-31) if this occurs.
  /// @see https://daveprotocol.com/#dave_mls_welcome-30
  #[napi]
  pub fn process_welcome(&mut self, welcome: Buffer) -> napi::Result<()> {
    self
      .inner
      .process_welcome(&welcome)
      .map_err(|err| napi_error!("Failed to process welcome: {err:?}"))?;

    Ok(())
  }

  /// Process a commit.
  /// @param commit The commit to process.
  /// @throws Will throw an error if the commit is invalid. Send an [opcode 31: dave_mls_invalid_commit_welcome](https://daveprotocol.com/#dave_mls_invalid_commit_welcome-31) if this occurs.
  /// @see https://daveprotocol.com/#dave_mls_announce_commit_transition-29
  #[napi]
  pub fn process_commit(&mut self, commit: Buffer) -> napi::Result<()> {
    self
      .inner
      .process_commit(&commit)
      .map_err(|err| napi_error!("Failed to process commit: {err:?}"))?;

    Ok(())
  }

  /// Get the verification code of another member of the group.
  /// This is the equivalent of `generateDisplayableCode(getPairwiseFingerprint(0, userId), 45, 5)`.
  /// @see https://daveprotocol.com/#displayable-codes
  #[napi(ts_return_type = "Promise<string>")]
  pub fn get_verification_code(&self, user_id: String) -> AsyncTask<AsyncSessionVerificationCode> {
    let result = self.get_pairwise_fingerprint_internal(0, user_id);
    let (ok, err) = {
      match result {
        Ok(value) => (Some(value), None),
        Err(err) => (None, Some(err)),
      }
    };
    AsyncTask::new(AsyncSessionVerificationCode {
      fingerprints: ok,
      error: err,
    })
  }

  /// Create a pairwise fingerprint of you and another member.
  /// @see https://daveprotocol.com/#verification-fingerprint
  #[napi(ts_return_type = "Promise<Buffer>")]
  pub fn get_pairwise_fingerprint(
    &self,
    version: u16,
    user_id: String,
  ) -> AsyncTask<AsyncPairwiseFingerprintSession> {
    let result = self.get_pairwise_fingerprint_internal(version, user_id);
    let (ok, err) = {
      match result {
        Ok(value) => (Some(value), None),
        Err(err) => (None, Some(err)),
      }
    };
    AsyncTask::new(AsyncPairwiseFingerprintSession {
      fingerprints: ok,
      error: err,
    })
  }

  fn get_pairwise_fingerprint_internal(
    &self,
    version: u16,
    user_id: String,
  ) -> napi::Result<[Vec<u8>; 2]> {
    let their_uid = user_id
      .parse::<u64>()
      .map_err(|_| napi_invalid_arg_error!("Invalid user id"))?;

    let fingerprints = self
      .inner
      .get_key_fingerprint_pair(version, their_uid)
      .map_err(|err| napi_error!("Failed to get key fingerprint pair: {err:?}"))?;

    Ok(fingerprints)
  }

  /// End-to-end encrypt a packet.
  /// @param mediaType The type of media to encrypt
  /// @param codec The codec of the packet
  /// @param packet The packet to encrypt
  #[napi]
  pub fn encrypt(
    &mut self,
    media_type: MediaType,
    codec: Codec,
    packet: Buffer,
  ) -> napi::Result<Buffer> {
    let result = self
      .inner
      .encrypt(media_type, codec, &packet)
      .map_err(|err| napi_error!("Failed to encrypt: {err:?}"))?;

    Ok(Buffer::from(result.into_owned()))
  }

  /// End-to-end encrypt an opus packet.
  /// This is the shorthand for `encrypt(MediaType.AUDIO, Codec.OPUS, packet)`
  /// @param packet The packet to encrypt
  #[napi]
  pub fn encrypt_opus(&mut self, packet: Buffer) -> napi::Result<Buffer> {
    self.encrypt(MediaType::AUDIO, Codec::OPUS, packet)
  }

  /// Get encryption stats.
  /// @param [mediaType=MediaType.AUDIO] The media type, defaults to `MediaType.AUDIO`
  #[napi]
  pub fn get_encryption_stats(&self, media_type: Option<MediaType>) -> Option<EncryptionStats> {
    self
      .inner
      .get_encryption_stats(media_type)
      .map(|s| s.to_owned())
  }

  /// Decrypt an end-to-end encrypted packet.
  /// @param userId The user ID of the packet
  /// @param mediaType The type of media to decrypt
  /// @param packet The packet to decrypt
  #[napi]
  pub fn decrypt(
    &mut self,
    user_id: String,
    media_type: MediaType,
    packet: Buffer,
  ) -> napi::Result<Buffer> {
    let uid = user_id
      .parse::<u64>()
      .map_err(|_| napi_invalid_arg_error!("Invalid user id"))?;

    let result = self
      .inner
      .decrypt(uid, media_type, &packet)
      .map_err(|err| napi_error!("Failed to decrypt: {err:?}"))?;

    Ok(Buffer::from(result))
  }

  /// Get decryption stats.
  /// @param userId The user ID
  /// @param [mediaType=MediaType.AUDIO] The media type, defaults to `MediaType.AUDIO`
  #[napi]
  pub fn get_decryption_stats(
    &self,
    user_id: String,
    media_type: Option<MediaType>,
  ) -> napi::Result<Option<DecryptionStats>> {
    let uid = user_id
      .parse::<u64>()
      .map_err(|_| napi_invalid_arg_error!("Invalid user id"))?;

    let result = self
      .inner
      .get_decryption_stats(uid, media_type.unwrap_or(MediaType::AUDIO))
      .map_err(|err| napi_error!("Failed to get decryption stats: {err:?}"))?;

    Ok(result.map(|s| s.to_owned()))
  }

  /// Get the IDs of the users in the current group.
  /// @returns An array of user IDs, or an empty array if there is no group.
  #[napi]
  pub fn get_user_ids(&self) -> Vec<String> {
    self
      .inner
      .get_user_ids()
      .map(|ids| {
        ids
          .into_iter()
          .map(|id| id.to_string())
          .collect::<Vec<String>>()
      })
      .unwrap_or_default()
  }

  /// Check whether this user's key ratchet is in passthrough mode
  /// @param userId The user ID
  #[napi]
  pub fn can_passthrough(&self, user_id: String) -> napi::Result<bool> {
    let uid = user_id
      .parse::<u64>()
      .map_err(|_| napi_invalid_arg_error!("Invalid user id"))?;

    Ok(self.inner.can_passthrough(uid))
  }

  /// Set whether passthrough mode is enabled on all decryptors.
  /// @param passthroughMode Whether to enable passthrough mode
  /// @param [transition_expiry=10] The transition expiry (in seconds) to use when disabling passthrough mode, defaults to 10 seconds
  #[napi]
  pub fn set_passthrough_mode(&mut self, passthrough_mode: bool, transition_expiry: Option<u32>) {
    self
      .inner
      .set_passthrough_mode(passthrough_mode, transition_expiry);
  }

  /// @ignore
  #[napi]
  pub fn to_string(&self) -> napi::Result<String> {
    Ok(format!(
      "DAVESession {{ protocolVersion: {}, userId: {}, channelId: {}, ready: {}, status: {:?} }}",
      self.inner.protocol_version(),
      self.user_id(),
      self.channel_id(),
      self.ready(),
      self.status()
    ))
  }
}
