use pyo3::prelude::*;
use std::num::NonZeroU16;

use crate::signing_key_pair::SigningKeyPair;

#[pyclass(get_all)]
#[derive(Clone)]
pub struct CommitWelcome {
  pub commit: Vec<u8>,
  pub welcome: Option<Vec<u8>>,
}

impl From<davey::CommitWelcome> for CommitWelcome {
  fn from(cw: davey::CommitWelcome) -> Self {
    CommitWelcome {
      commit: cw.commit,
      welcome: cw.welcome,
    }
  }
}

#[pyclass]
pub struct DaveSession {
  inner: Box<davey::DaveSession>,
}

#[pymethods]
impl DaveSession {
  #[new]
  #[pyo3(signature = (protocol_version, user_id, channel_id, key_pair=None))]
  fn new(
    protocol_version: u16,
    user_id: u64,
    channel_id: u64,
    key_pair: Option<SigningKeyPair>,
  ) -> PyResult<Self> {
    let protocol_version =
      NonZeroU16::new(protocol_version).ok_or(py_value_error!("Unsupported protocol version"))?;

    let signing_key_pair = key_pair.map(|kp| davey::SigningKeyPair {
      private: kp.private.to_vec(),
      public: kp.public.to_vec(),
    });

    let session = davey::DaveSession::new(
      protocol_version,
      user_id,
      channel_id,
      signing_key_pair.as_ref(),
    )
    .map_err(|e| py_value_error!("Failed to initialize session: {:?}", e))?;

    Ok(Self {
      inner: Box::new(session),
    })
  }

  #[pyo3(signature = (protocol_version, user_id, channel_id, key_pair=None))]
  fn reinit(
    &mut self,
    protocol_version: u16,
    user_id: u64,
    channel_id: u64,
    key_pair: Option<SigningKeyPair>,
  ) -> PyResult<()> {
    let protocol_version =
      NonZeroU16::new(protocol_version).ok_or(py_value_error!("Unsupported protocol version"))?;

    let signing_key_pair = key_pair.map(|kp| davey::SigningKeyPair {
      private: kp.private.to_vec(),
      public: kp.public.to_vec(),
    });

    self
      .inner
      .reinit(
        protocol_version,
        user_id,
        channel_id,
        signing_key_pair.as_ref(),
      )
      .map_err(|err| py_value_error!("Failed to re-initialize session: {err:?}"))?;

    Ok(())
  }

  fn reset(&mut self) -> PyResult<()> {
    self
      .inner
      .reset()
      .map_err(|err| py_value_error!("Failed to reset session: {err:?}"))?;

    Ok(())
  }

  #[getter]
  fn protocol_version(&self) -> u16 {
    self.inner.protocol_version().get()
  }

  #[getter]
  fn user_id(&self) -> u64 {
    self.inner.user_id()
  }

  #[getter]
  fn channel_id(&self) -> u64 {
    self.inner.channel_id()
  }

  #[getter]
  fn epoch(&self) -> Option<u64> {
    self.inner.epoch().map(|e| e.as_u64())
  }

  #[getter]
  fn own_leaf_index(&self) -> Option<u32> {
    self.inner.own_leaf_index().map(|e| e.u32())
  }

  #[getter]
  fn ciphersuite(&self) -> u16 {
    self.inner.ciphersuite() as u16
  }

  #[getter]
  fn status(&self) -> davey::SessionStatus {
    self.inner.status()
  }

  #[getter]
  fn ready(&self) -> bool {
    self.inner.is_ready()
  }

  fn get_epoch_authenticator(&self) -> Option<&[u8]> {
    self.inner.get_epoch_authenticator().map(|ea| ea.as_slice())
  }

  #[getter]
  fn voice_privacy_code(&self) -> Option<String> {
    self.inner.voice_privacy_code().map(|vpc| vpc.to_string())
  }

  fn set_external_sender(&mut self, external_sender_data: &[u8]) -> PyResult<()> {
    self
      .inner
      .set_external_sender(external_sender_data)
      .map_err(|err| py_value_error!("Failed to set external sender: {err:?}"))?;

    Ok(())
  }

  fn get_serialized_key_package(&mut self) -> PyResult<Vec<u8>> {
    let key_package = self
      .inner
      .create_key_package()
      .map_err(|err| py_value_error!("Failed to create key package: {err:?}"))?;

    Ok(key_package)
  }

  #[pyo3(signature = (operation_type, proposals, expected_user_ids=None))]
  fn process_proposals(
    &mut self,
    operation_type: davey::ProposalsOperationType,
    proposals: &[u8],
    expected_user_ids: Option<Vec<u64>>,
  ) -> PyResult<Option<CommitWelcome>> {
    let result = self
      .inner
      .process_proposals(operation_type, proposals, expected_user_ids.as_deref())
      .map_err(|err| py_value_error!("Failed to process proposals: {err:?}"))?;

    Ok(result.map(CommitWelcome::from))
  }

  fn process_welcome(&mut self, welcome: &[u8]) -> PyResult<()> {
    self
      .inner
      .process_welcome(welcome)
      .map_err(|err| py_value_error!("Failed to process welcome: {err:?}"))?;

    Ok(())
  }

  fn process_commit(&mut self, commit: &[u8]) -> PyResult<()> {
    self
      .inner
      .process_commit(commit)
      .map_err(|err| py_value_error!("Failed to process commit: {err:?}"))?;

    Ok(())
  }

  fn get_verification_code(&self, user_id: u64) -> PyResult<String> {
    self
      .inner
      .get_verification_code(user_id)
      .map_err(|e| py_value_error!("failed to generate verification code: {:?}", e))
  }

  fn get_pairwise_fingerprint(&self, version: u16, user_id: u64) -> PyResult<Vec<u8>> {
    self
      .inner
      .get_pairwise_fingerprint(version, user_id)
      .map_err(|e| py_value_error!("failed to generate pairwise fingerprint: {:?}", e))
  }

  fn encrypt(
    &mut self,
    media_type: davey::MediaType,
    codec: davey::Codec,
    packet: &[u8],
  ) -> PyResult<Vec<u8>> {
    let result = self
      .inner
      .encrypt(media_type, codec, packet)
      .map_err(|err| py_value_error!("Failed to encrypt: {err:?}"))?;

    Ok(result.into_owned().to_vec())
  }

  fn encrypt_opus(&mut self, packet: &[u8]) -> PyResult<Vec<u8>> {
    self.encrypt(davey::MediaType::AUDIO, davey::Codec::OPUS, packet)
  }

  #[pyo3(signature = (media_type=None))]
  fn get_encryption_stats(
    &self,
    media_type: Option<davey::MediaType>,
  ) -> Option<davey::EncryptionStats> {
    self
      .inner
      .get_encryption_stats(media_type)
      .map(|s| s.to_owned())
  }

  fn decrypt(
    &mut self,
    user_id: u64,
    media_type: davey::MediaType,
    packet: &[u8],
  ) -> PyResult<Vec<u8>> {
    let result = self
      .inner
      .decrypt(user_id, media_type, packet)
      .map_err(|err| py_value_error!("Failed to decrypt: {err:?}"))?;

    Ok(result.to_owned().to_vec())
  }

  #[pyo3(signature = (user_id, media_type=None))]
  fn get_decryption_stats(
    &self,
    user_id: u64,
    media_type: Option<davey::MediaType>,
  ) -> PyResult<Option<davey::DecryptionStats>> {
    let result = self
      .inner
      .get_decryption_stats(user_id, media_type.unwrap_or(davey::MediaType::AUDIO))
      .map_err(|err| py_value_error!("Failed to get decryption stats: {err:?}"))?;

    Ok(result.map(|s| s.to_owned()))
  }

  fn get_user_ids(&self) -> Vec<String> {
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

  fn can_passthrough(&self, user_id: u64) -> bool {
    self.inner.can_passthrough(user_id)
  }

  #[pyo3(signature = (passthrough_mode, transition_expiry=None))]
  fn set_passthrough_mode(&mut self, passthrough_mode: bool, transition_expiry: Option<u32>) {
    self
      .inner
      .set_passthrough_mode(passthrough_mode, transition_expiry);
  }

  fn __repr__(&self) -> &'static str {
    let s = format!(
      "<DaveSession protocol_version={}, user_id={}, channel_id={}, ready={}, status={:?}>",
      self.inner.protocol_version(),
      self.inner.user_id(),
      self.inner.channel_id(),
      self.inner.is_ready(),
      self.inner.status()
    );
    Box::leak(s.into_boxed_str())
  }
}
