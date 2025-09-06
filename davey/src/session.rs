#[cfg(feature = "napi")]
use napi_derive::napi;
use num_derive::FromPrimitive;
use openmls::{
  group::{ProcessMessageError, *},
  prelude::{hash_ref::ProposalRef, tls_codec::Serialize, *},
  schedule::EpochAuthenticator,
};
use openmls_basic_credential::SignatureKeyPair;
use openmls_rust_crypto::OpenMlsRustCrypto;
#[cfg(feature = "pyo3")]
use pyo3::prelude::*;
use std::{borrow::Cow, collections::HashMap, fmt::Debug, num::NonZeroU16};
use tracing::{debug, trace, warn};

use crate::{
  errors::*, generate_key_fingerprint, pairwise_fingerprints_internal,
  signing_key_pair::SigningKeyPair,
};

use super::{
  cryptor::{
    AES_GCM_128_KEY_BYTES, Codec, MediaType, OPUS_SILENCE_PACKET,
    decryptor::{DecryptionStats, Decryptor},
    encryptor::{EncryptionStats, Encryptor},
    hash_ratchet::HashRatchet,
  },
  generate_displayable_code_internal,
};

const USER_MEDIA_KEY_BASE_LABEL: &str = "Discord Secure Frames v0";

/// Gets the [`Ciphersuite`] for a dave protocol version.
fn dave_protocol_version_to_ciphersuite(
  protocol_version: NonZeroU16,
) -> Result<Ciphersuite, UnsupportedProtocolVersion> {
  match protocol_version.get() {
    1 => Ok(Ciphersuite::MLS_128_DHKEMP256_AES128GCM_SHA256_P256),
    _ => Err(UnsupportedProtocolVersion(protocol_version)),
  }
}

/// Gets the [`Capabilities`] for a [`DAVEProtocolVersion`].
fn dave_protocol_version_to_capabilities(
  protocol_version: NonZeroU16,
) -> Result<Capabilities, UnsupportedProtocolVersion> {
  match protocol_version.get() {
    1 => Ok(
      Capabilities::builder()
        .versions(vec![ProtocolVersion::Mls10])
        .ciphersuites(vec![dave_protocol_version_to_ciphersuite(
          protocol_version,
        )?])
        .extensions(vec![])
        .proposals(vec![])
        .credentials(vec![CredentialType::Basic])
        .build(),
    ),
    _ => Err(UnsupportedProtocolVersion(protocol_version)),
  }
}

/// The maximum supported version of the DAVE protocol.
#[cfg_attr(feature = "napi", napi)]
pub const DAVE_PROTOCOL_VERSION: u16 = 1;

#[cfg_attr(feature = "napi", napi)]
#[cfg_attr(feature = "pyo3", pyclass(eq, eq_int, rename_all = "snake_case"))]
#[derive(Clone, Copy, Debug, FromPrimitive, PartialEq, Eq)]
pub enum ProposalsOperationType {
  APPEND = 0,
  REVOKE = 1,
}

#[cfg_attr(feature = "napi", napi)]
#[cfg_attr(feature = "pyo3", pyclass(eq, eq_int, rename_all = "snake_case"))]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[allow(non_camel_case_types)]
pub enum SessionStatus {
  INACTIVE = 0,
  PENDING = 1,
  AWAITING_RESPONSE = 2,
  ACTIVE = 3,
}

/// Contains the commit and optional welcome for [dave_mls_commit_welcome (28)](https://daveprotocol.com/#dave_mls_commit_welcome-28).
pub struct CommitWelcome {
  pub commit: Vec<u8>,
  pub welcome: Option<Vec<u8>>,
}

pub struct DaveSession {
  protocol_version: NonZeroU16,
  provider: OpenMlsRustCrypto,
  ciphersuite: Ciphersuite,
  group_id: GroupId,
  signer: SignatureKeyPair,
  credential_with_key: CredentialWithKey,

  external_sender: Option<ExternalSender>,
  group: Option<MlsGroup>,
  status: SessionStatus,
  is_ready: bool,

  privacy_code: String,
  encryptor: Encryptor,
  decryptors: HashMap<u64, Decryptor>,
}

impl DaveSession {
  /// Creates a DAVE session. If no key pair is passed, one will be generated automatically.
  pub fn new(
    protocol_version: NonZeroU16,
    user_id: u64,
    channel_id: u64,
    key_pair: Option<&SigningKeyPair>,
  ) -> Result<Self, InitError> {
    let (ciphersuite, group_id, signer, credential_with_key) =
      Self::common_init(protocol_version, user_id, channel_id, key_pair)?;

    Ok(DaveSession {
      protocol_version,
      ciphersuite,
      provider: OpenMlsRustCrypto::default(),
      group_id,
      signer,
      credential_with_key,
      external_sender: None,
      group: None,
      status: SessionStatus::INACTIVE,
      is_ready: false,
      privacy_code: String::new(),
      encryptor: Encryptor::new(),
      decryptors: HashMap::new(),
    })
  }

  /// Resets and re-initializes the session.
  pub fn reinit(
    &mut self,
    protocol_version: NonZeroU16,
    user_id: u64,
    channel_id: u64,
    key_pair: Option<&SigningKeyPair>,
  ) -> Result<(), ReinitError> {
    self.reset()?;

    let (ciphersuite, group_id, signer, credential_with_key) =
      Self::common_init(protocol_version, user_id, channel_id, key_pair)?;

    self.protocol_version = protocol_version;
    self.ciphersuite = ciphersuite;
    self.group_id = group_id;
    self.signer = signer;
    self.credential_with_key = credential_with_key;
    self.privacy_code.clear();
    self.encryptor = Encryptor::new();
    self.decryptors.clear();
    self.is_ready = false;

    if self.external_sender.is_some() {
      self.create_pending_group()?;
    }

    Ok(())
  }

  fn common_init(
    protocol_version: NonZeroU16,
    user_id: u64,
    channel_id: u64,
    key_pair: Option<&SigningKeyPair>,
  ) -> Result<(Ciphersuite, GroupId, SignatureKeyPair, CredentialWithKey), InitError> {
    let ciphersuite = dave_protocol_version_to_ciphersuite(protocol_version)?;
    let credential = BasicCredential::new(user_id.to_be_bytes().into());
    let group_id = GroupId::from_slice(&channel_id.to_be_bytes());
    let signer = if let Some(key_pair) = key_pair {
      SignatureKeyPair::from_raw(
        ciphersuite.signature_algorithm(),
        key_pair.private.clone(),
        key_pair.public.clone(),
      )
    } else {
      SignatureKeyPair::new(ciphersuite.signature_algorithm())?
    };
    let credential_with_key = CredentialWithKey {
      credential: credential.into(),
      signature_key: signer.public().into(),
    };

    Ok((ciphersuite, group_id, signer, credential_with_key))
  }

  /// Resets the session by deleting the group and clearing the storage.
  /// If you want to re-initialize the session, use [Self::reinit].
  pub fn reset(&mut self) -> Result<(), ResetError> {
    debug!("Resetting MLS session");

    // Delete group
    if let Some(mut group) = self.group.take() {
      group.delete(self.provider.storage())?;
    }

    // Clear storage
    self.provider.storage().values.write().unwrap().clear();

    self.status = SessionStatus::INACTIVE;

    Ok(())
  }

  /// The DAVE protocol version used for this session.
  pub fn protocol_version(&self) -> NonZeroU16 {
    self.protocol_version
  }

  /// The user ID for this session.
  pub fn user_id(&self) -> u64 {
    u64::from_be_bytes(
      self
        .credential_with_key
        .credential
        .serialized_content()
        .try_into()
        .expect("Failed to convert our user id"),
    )
  }

  /// The channel ID (group ID in MLS standards) for this session.
  pub fn channel_id(&self) -> u64 {
    u64::from_be_bytes(
      self
        .group_id
        .as_slice()
        .try_into()
        .expect("failed to convert channel id"),
    )
  }

  /// The group of this session.
  pub fn group(&self) -> Option<&MlsGroup> {
    self.group.as_ref()
  }

  /// The epoch for the current group.
  pub fn epoch(&self) -> Option<GroupEpoch> {
    self.group.as_ref().map(|group| group.epoch())
  }

  /// Your own leaf index for the current group.
  pub fn own_leaf_index(&self) -> Option<LeafNodeIndex> {
    self.group.as_ref().map(|group| group.own_leaf_index())
  }

  /// The ciphersuite being used in this session.
  pub fn ciphersuite(&self) -> Ciphersuite {
    self.ciphersuite
  }

  /// The status of this session.
  pub fn status(&self) -> SessionStatus {
    self.status
  }

  /// Whether this session is ready to encrypt/decrypt frames.
  pub fn is_ready(&self) -> bool {
    self.is_ready
  }

  /// Get the epoch authenticator of this session's group.
  pub fn get_epoch_authenticator(&self) -> Option<&EpochAuthenticator> {
    self.group.as_ref().map(|group| group.epoch_authenticator())
  }

  /// Get the voice privacy code of this session's group.
  /// A new privacy code is created and cached each time a new transition is executed.
  /// See [Displayable Codes](https://daveprotocol.com/#displayable-codes)
  pub fn voice_privacy_code(&self) -> Option<&str> {
    (!self.privacy_code.is_empty()).then_some(&self.privacy_code)
  }

  /// Set the external sender this session will recieve from.
  /// See [dave_mls_external_sender_package (25)](https://daveprotocol.com/#dave_mls_external_sender_package-25).
  pub fn set_external_sender(
    &mut self,
    external_sender_data: &[u8],
  ) -> Result<(), SetExternalSenderError> {
    if self.status == SessionStatus::AWAITING_RESPONSE || self.status == SessionStatus::ACTIVE {
      return Err(SetExternalSenderError::AlreadyInGroup);
    }

    // Delete group to avoid clashing
    if let Some(mut group) = self.group.take() {
      group.delete(self.provider.storage())?;
    }

    let external_sender = ExternalSender::tls_deserialize_exact_bytes(external_sender_data)?;

    self.external_sender = Some(external_sender);
    debug!("External sender set.");

    self.create_pending_group()?;

    Ok(())
  }

  /// Create, store, and return the serialized key package.
  /// Key packages are not meant to be reused, and will be recreated on each call of this function.
  /// See [dave_mls_key_package (26)](https://daveprotocol.com/#dave_mls_key_package-26)
  pub fn create_key_package(&mut self) -> Result<Vec<u8>, CreateKeyPackageError> {
    // Set lifetime to max time span: https://daveprotocol.com/#validation
    let lifetime = {
      const MAX_TIMESPAN_LIFETIME: [u8; 0x10] = [
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // not_before
        0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, // not_after
      ];
      Lifetime::tls_deserialize_exact_bytes(&MAX_TIMESPAN_LIFETIME)
        .expect("failed to deserialize statically defined lifetime")
    };

    // This key package is stored in the provider for later
    let key_package = KeyPackage::builder()
      .key_package_extensions(Extensions::empty())
      .leaf_node_capabilities(dave_protocol_version_to_capabilities(self.protocol_version).unwrap())
      .key_package_lifetime(lifetime)
      .build(
        self.ciphersuite,
        &self.provider,
        &self.signer,
        self.credential_with_key.clone(),
      )?;

    let buffer = key_package
      .key_package()
      .tls_serialize_detached()
      .expect("failed to serialize key package");

    debug!("Created key package for channel {}", self.channel_id());

    Ok(buffer)
  }

  fn create_pending_group(&mut self) -> Result<(), PendingGroupError> {
    let Some(external_sender) = &self.external_sender else {
      return Err(PendingGroupError::NoExternalSender);
    };

    let mls_group_create_config = MlsGroupCreateConfig::builder()
      .with_group_context_extensions(Extensions::single(Extension::ExternalSenders(vec![
        external_sender.clone(),
      ])))?
      .ciphersuite(self.ciphersuite)
      .capabilities(dave_protocol_version_to_capabilities(self.protocol_version).unwrap())
      .use_ratchet_tree_extension(true)
      .wire_format_policy(PURE_PLAINTEXT_WIRE_FORMAT_POLICY)
      .build();

    let group = MlsGroup::new_with_group_id(
      &self.provider,
      &self.signer,
      &mls_group_create_config,
      self.group_id.clone(),
      self.credential_with_key.clone(),
    )?;

    self.group = Some(group);
    self.status = SessionStatus::PENDING;

    debug!("Created pending group for channel {}", self.channel_id());

    Ok(())
  }

  /// Process proposals from [dave_mls_proposals (27)](https://daveprotocol.com/#dave_mls_proposals-27).
  /// If the user wants to validate that all users in proposals are expected to be in the group, pass them in `expected_user_ids`.
  /// If a [CommitWelcome] is returned, the user should send a [dave_mls_commit_welcome (28)](https://daveprotocol.com/#dave_mls_commit_welcome-28) to the gateway.
  pub fn process_proposals(
    &mut self,
    operation_type: ProposalsOperationType,
    proposals: &[u8],
    expected_user_ids: Option<&[u64]>,
  ) -> Result<Option<CommitWelcome>, ProcessProposalsError> {
    let Some(group) = &mut self.group else {
      return Err(ProcessProposalsError::NoGroup);
    };

    debug!("Processing proposals, optype {:?}", operation_type);

    let proposals: Vec<u8> = VLBytes::tls_deserialize_exact_bytes(proposals)
      .map_err(ProcessProposalsError::DeserializeProposalFailed)?
      .into();
    let mut commit_adds_members = false;

    if operation_type == ProposalsOperationType::APPEND {
      let mut remaining_bytes: &[u8] = &proposals;
      while !remaining_bytes.is_empty() {
        let (mls_message, leftover) = MlsMessageIn::tls_deserialize_bytes(remaining_bytes)
          .map_err(ProcessProposalsError::DeserializeMessageFailed)?;
        remaining_bytes = leftover;

        let protocol_message = mls_message
          .try_into_protocol_message()
          .map_err(ProcessProposalsError::MessageNotPrivateOrPublic)?;

        let processed_message = group.process_message(&self.provider, protocol_message)?;

        match processed_message.into_content() {
          ProcessedMessageContent::ProposalMessage(proposal) => {
            if let Proposal::Add(add_proposal) = proposal.proposal() {
              let incoming_user_id = u64::from_be_bytes(
                add_proposal
                  .key_package()
                  .leaf_node()
                  .credential()
                  .serialized_content()
                  .try_into()
                  .map_err(ProcessProposalsError::CredentialContentConvertFailed)?,
              );

              debug!("Storing add proposal for user {incoming_user_id}");

              if let Some(ids) = expected_user_ids
                && !ids.contains(&incoming_user_id)
              {
                return Err(ProcessProposalsError::UnexpectedUser(incoming_user_id));
              }

              commit_adds_members = true;
            } else if let Proposal::Remove(remove_proposal) = proposal.proposal() {
              let leaf_index = remove_proposal.removed();
              let member = group.member(leaf_index);
              let outgoing_user_id = {
                if let Some(member) = member {
                  u64::from_be_bytes(
                    member
                      .serialized_content()
                      .try_into()
                      .unwrap_or([0, 0, 0, 0, 0, 0, 0, 0]),
                  )
                } else {
                  0u64
                }
              };
              debug!(
                "Storing remove proposal for user {outgoing_user_id} (leaf index: {leaf_index})",
              );
            }

            if proposal.proposal_or_ref_type() == ProposalOrRefType::Proposal {
              warn!(
                "This next proposal isn't a reference, so our commit is probably going to be rejected",
              );
            }

            group
              .store_pending_proposal(self.provider.storage(), *proposal)
              .map_err(ProcessProposalsError::StorePendingProposalFailed)?;
          }
          _ => return Err(ProcessProposalsError::MessageNotProposal),
        }
      }
    } else {
      let mut remaining_bytes: &[u8] = &proposals;
      while !remaining_bytes.is_empty() {
        let (proposal_ref, leftover) = ProposalRef::tls_deserialize_bytes(remaining_bytes)
          .map_err(ProcessProposalsError::DeserializeProposalRefFailed)?;
        remaining_bytes = leftover;

        debug!("Removing pending proposal {:?}", proposal_ref);
        group.remove_pending_proposal(self.provider.storage(), &proposal_ref)?;
      }
    }

    // Revert to previous state if there arent any more pending proposals
    let queued_proposal = group.pending_proposals().next();
    if queued_proposal.is_none() {
      debug!("No proposals left to commit, reverting to previous state");
      group
        .clear_pending_commit(self.provider.storage())
        .map_err(ProcessProposalsError::RemovingPendingCommitFailed)?;
      if self.status == SessionStatus::AWAITING_RESPONSE {
        self.status = {
          if self.is_ready {
            SessionStatus::ACTIVE
          } else {
            SessionStatus::PENDING
          }
        }
      }
      return Ok(None);
    }

    // libdave seems to overwrite pendingGroupCommit_ and then not use it anywhere else...
    if group.pending_commit().is_some() {
      warn!("A pending commit was already created! Removing...");
      group
        .clear_pending_commit(self.provider.storage())
        .map_err(ProcessProposalsError::RemovingPendingCommitFailed)?;
    }

    let (commit, welcome, _group_info) = group
      .commit_to_pending_proposals(&self.provider, &self.signer)
      .map_err(ProcessProposalsError::CommitToPendingProposalsFailed)?;

    self.status = SessionStatus::AWAITING_RESPONSE;

    let commit = commit
      .tls_serialize_detached()
      .expect("failed to serialize commit");

    let welcome = if commit_adds_members {
      let Some(mls_message_out) = welcome else {
        panic!("welcome was not returned when there are new members")
      };
      let MlsMessageBodyOut::Welcome(welcome) = mls_message_out.body() else {
        panic!("message was not a welcome")
      };

      Some(
        welcome
          .tls_serialize_detached()
          .expect("failed to serialize welcome"),
      )
    } else {
      None
    };

    Ok(Some(CommitWelcome { commit, welcome }))
  }

  /// Process a welcome message from [dave_mls_welcome (30)](https://daveprotocol.com/#dave_mls_welcome-30).
  /// Send a [dave_mls_invalid_commit_welcome (31)](https://daveprotocol.com/#dave_mls_invalid_commit_welcome-31) if the welcome couldn't be processed.
  pub fn process_welcome(&mut self, welcome: &[u8]) -> Result<(), ProcessWelcomeError> {
    if self.group.is_some() && self.status == SessionStatus::ACTIVE {
      return Err(ProcessWelcomeError::AlreadyInGroup);
    }

    let Some(external_sender) = &self.external_sender else {
      return Err(ProcessWelcomeError::NoExternalSender);
    };

    // TODO we are skipping using recognized user IDs in here for now
    // See https://github.com/discord/libdave/blob/6e5ffbc1cb4eef6be96e8115c4626be598b7e501/cpp/src/dave/mls/session.cpp#L519

    debug!("Processing welcome");

    let mls_group_config = MlsGroupJoinConfig::builder()
      .use_ratchet_tree_extension(true)
      .wire_format_policy(PURE_PLAINTEXT_WIRE_FORMAT_POLICY)
      .build();

    let welcome = Welcome::tls_deserialize_exact_bytes(welcome)?;

    let staged_join =
      StagedWelcome::new_from_welcome(&self.provider, &mls_group_config, welcome, None)?;

    let external_senders = staged_join.group_context().extensions().external_senders();
    let Some(external_senders) = external_senders else {
      return Err(ProcessWelcomeError::ExpectedExternalSenderExtension);
    };

    let [join_external_sender] = external_senders.as_slice() else {
      return Err(ProcessWelcomeError::ExpectedOneExternalSender);
    };

    if join_external_sender != external_sender {
      return Err(ProcessWelcomeError::UnexpectedExternalSender);
    }

    let group = staged_join.into_group(&self.provider)?;

    if let Some(mut pending_group) = self.group.take() {
      pending_group
        .delete(self.provider.storage())
        .map_err(ProcessWelcomeError::DeletingPendingGroupFailed)?;
    }

    debug!(
      "Welcomed to group successfully, our leaf index is {:?}, our epoch is {:?}",
      group.own_leaf_index().u32(),
      group.epoch().as_u64()
    );
    self.group = Some(group);
    self.status = SessionStatus::ACTIVE;
    self.update_ratchets()?;

    Ok(())
  }

  /// Process a commit from [dave_mls_announce_commit_transition (29)](https://daveprotocol.com/#dave_mls_announce_commit_transition-29).
  /// Send a [dave_mls_invalid_commit_welcome (29)](https://daveprotocol.com/#dave_mls_announce_commit_transition-29) if the commit couldn't be processed.
  pub fn process_commit(&mut self, commit: &[u8]) -> Result<(), ProcessCommitError> {
    let Some(group) = &mut self.group else {
      return Err(ProcessCommitError::NoGroup);
    };

    if self.status == SessionStatus::PENDING {
      return Err(ProcessCommitError::PendingGroup);
    }

    debug!("Processing commit");

    let mls_message = MlsMessageIn::tls_deserialize_exact_bytes(commit)
      .map_err(ProcessCommitError::DeserializeMessage)?;

    let protocol_message = mls_message
      .try_into_protocol_message()
      .map_err(ProcessCommitError::MessageNotPrivateOrPublic)?;

    if protocol_message.group_id().as_slice() != self.group_id.as_slice() {
      return Err(ProcessCommitError::MessageForDifferentGroup);
    }

    match group.process_message(&self.provider, protocol_message) {
      Ok(message) => match message.into_content() {
        ProcessedMessageContent::StagedCommitMessage(staged_commit) => {
          group.merge_staged_commit(&self.provider, *staged_commit)?;
        }
        _ => return Err(ProcessCommitError::ProcessedMessageNotStagedCommit),
      },
      Err(ProcessMessageError::InvalidCommit(StageCommitError::OwnCommit)) => {
        // This is our own commit, lets merge pending instead
        debug!("Found own commit, merging pending commit instead.");
        group.merge_pending_commit(&self.provider)?;
      }
      Err(error) => return Err(ProcessCommitError::ProcessingMessageFailed(error)),
    }

    debug!(
      "Commit processed successfully, our leaf index is {:?}, our epoch is {:?}",
      group.own_leaf_index().u32(),
      group.epoch().as_u64()
    );
    self.status = SessionStatus::ACTIVE;
    self.update_ratchets()?;

    Ok(())
  }

  /// Get the verification code of another member of the group.
  /// This is the equivalent of `generateDisplayableCode(getPairwiseFingerprint(0, userId), 45, 5)`.
  /// See [Displayable Codes](https://daveprotocol.com/#displayable-codes) in the DAVE whitepaper.
  pub fn get_verification_code(&self, user_id: u64) -> Result<String, GetVerificationCodeError> {
    let fingerprints = self.get_key_fingerprint_pair(0, user_id)?;
    let output = pairwise_fingerprints_internal(fingerprints)?;
    let code = generate_displayable_code_internal(&output, 45, 5)?;
    Ok(code)
  }

  /// Create a pairwise fingerprint of you and another member.
  /// See [Verification Fingerprint](https://daveprotocol.com/#verification-fingerprint) in the DAVE whitepaper.
  pub fn get_pairwise_fingerprint(
    &self,
    version: u16,
    user_id: u64,
  ) -> Result<Vec<u8>, GetPairwiseFingerprintError> {
    let fingerprints = self.get_key_fingerprint_pair(version, user_id)?;
    let pairwise_fingerprint = pairwise_fingerprints_internal(fingerprints)?;

    Ok(pairwise_fingerprint)
  }

  /// Get a pair of key fingerprints, one local and one from a user.
  /// For internal use in creating pairwise fingerprints.
  pub fn get_key_fingerprint_pair(
    &self,
    version: u16,
    user_id: u64,
  ) -> Result<[Vec<u8>; 2], GetPairwiseFingerprintError> {
    if self.status == SessionStatus::PENDING {
      return Err(GetPairwiseFingerprintError::NoEstablishedGroup);
    }
    let Some(group) = &self.group else {
      return Err(GetPairwiseFingerprintError::NoEstablishedGroup);
    };

    let our_uid = self.user_id();
    let their_uid = user_id;

    let member = group.members().find(|member| {
      let uid = u64::from_be_bytes(
        member
          .credential
          .serialized_content()
          .try_into()
          .unwrap_or([0, 0, 0, 0, 0, 0, 0, 0]),
      );
      uid == their_uid
    });

    let Some(member) = member else {
      return Err(GetPairwiseFingerprintError::UserNotInGroup);
    };

    Ok([
      generate_key_fingerprint(version, self.signer.public(), our_uid)?,
      generate_key_fingerprint(version, &member.signature_key, their_uid)?,
    ])
  }

  /// Should only be called when the session has a group
  fn update_ratchets(&mut self) -> Result<(), UpdateRatchetsError> {
    let group = self
      .group
      .as_ref()
      .expect("update ratchets called without a group");
    debug!(
      "Updating MLS ratchets for {:?} users",
      group.members().count()
    );

    // Update decryptors
    for member in group.members() {
      let Ok(user_id_bytes) = TryInto::<[u8; 8]>::try_into(member.credential.serialized_content())
      else {
        warn!("Failed to get uid for member index {:?}", member.index);
        continue;
      };
      let uid = u64::from_be_bytes(user_id_bytes);

      // Exclude making a decryptor for ourselves
      if uid == self.user_id() {
        continue;
      }

      let ratchet = self.get_key_ratchet(uid)?;
      let decryptor = self.decryptors.entry(uid).or_insert_with(|| {
        debug!("Creating decryptor for user {uid:?}");
        Decryptor::new()
      });
      decryptor.transition_to_key_ratchet(ratchet);
    }

    // Remove old decryptors
    let current_members: Vec<u64> = group
      .members()
      .map(|member| {
        u64::from_be_bytes(
          member
            .credential
            .serialized_content()
            .try_into()
            .unwrap_or([0, 0, 0, 0, 0, 0, 0, 0]),
        )
      })
      .collect();
    self
      .decryptors
      .retain(|&uid, _| current_members.contains(&uid));

    // Update encryptor
    let user_id = self.user_id();
    self
      .encryptor
      .set_key_ratchet(self.get_key_ratchet(user_id)?);

    // Update privacy code
    let old_code = self.privacy_code.clone();
    let epoch_authenticator = self.group.as_ref().unwrap().epoch_authenticator();
    self.privacy_code = generate_displayable_code_internal(epoch_authenticator.as_slice(), 30, 5)?;
    if self.privacy_code != old_code {
      debug!("New Voice Privacy Code: {:?}", self.privacy_code);
    }

    self.is_ready = true;

    Ok(())
  }

  /// See [Sender Key Derivation](https://daveprotocol.com/#sender-key-derivation).
  fn get_key_ratchet(&self, user_id: u64) -> Result<HashRatchet, UpdateRatchetsError> {
    if self.status == SessionStatus::PENDING {
      return Err(UpdateRatchetsError::NoEstablishedGroup);
    }
    let Some(group) = &self.group else {
      return Err(UpdateRatchetsError::NoEstablishedGroup);
    };

    let base_secret = group
      .export_secret(
        self.provider.crypto(),
        USER_MEDIA_KEY_BASE_LABEL,
        &user_id.to_le_bytes(),
        AES_GCM_128_KEY_BYTES,
      )
      .map_err(UpdateRatchetsError::ExportingSecretFailed)?;

    trace!("Got base secret for user {:?}: {:?}", user_id, base_secret);
    Ok(HashRatchet::new(base_secret))
  }

  /// End-to-end encrypt a packet.
  pub fn encrypt<'a>(
    &mut self,
    media_type: MediaType,
    codec: Codec,
    packet: &'a [u8],
  ) -> Result<Cow<'a, [u8]>, EncryptError> {
    if !self.is_ready {
      return Err(EncryptError::NotReady);
    }

    // Return the packet back to the client (passthrough) if the packet is a silence packet
    // This may change in the future, see: https://daveprotocol.com/#silence-packets
    if packet == OPUS_SILENCE_PACKET {
      return Ok(Cow::Borrowed(packet));
    }

    let mut out_size: usize = 0;
    let mut encrypted_buffer =
      vec![0u8; Encryptor::get_max_ciphertext_byte_size(&media_type, packet.len())];

    let success = self.encryptor.encrypt(
      &media_type,
      codec,
      packet,
      &mut encrypted_buffer,
      &mut out_size,
    );
    if !success {
      return Err(EncryptError::EncryptionFailed);
    }
    encrypted_buffer.resize(out_size, 0);

    Ok(Cow::Owned(encrypted_buffer))
  }

  /// End-to-end encrypt an opus packet.
  /// This is the shorthand for `encrypt(MediaType.AUDIO, Codec.OPUS, packet)`
  pub fn encrypt_opus<'a>(&mut self, packet: &'a [u8]) -> Result<Cow<'a, [u8]>, EncryptError> {
    self.encrypt(MediaType::AUDIO, Codec::OPUS, packet)
  }

  /// Get encryption stats.
  pub fn get_encryption_stats(&self, media_type: Option<MediaType>) -> Option<&EncryptionStats> {
    self
      .encryptor
      .stats
      .get(&media_type.unwrap_or(MediaType::AUDIO))
  }

  /// Decrypt an end-to-end encrypted packet.
  pub fn decrypt(
    &mut self,
    user_id: u64,
    media_type: MediaType,
    packet: &[u8],
  ) -> Result<Vec<u8>, DecryptError> {
    let Some(decryptor) = self.decryptors.get_mut(&user_id) else {
      return Err(DecryptError::NoDecryptorForUser);
    };

    let mut frame = vec![0u8; Decryptor::get_max_plaintext_byte_size(media_type, packet.len())];
    let frame_length = decryptor.decrypt(media_type, packet, &mut frame)?;

    frame.resize(frame_length, 0);
    Ok(frame)
  }

  /// Get decryption stats.
  pub fn get_decryption_stats(
    &self,
    user_id: u64,
    media_type: MediaType,
  ) -> Result<Option<&DecryptionStats>, NoDecryptorForUser> {
    let Some(decryptor) = self.decryptors.get(&user_id) else {
      return Err(NoDecryptorForUser);
    };

    Ok(decryptor.stats.get(&media_type))
  }

  /// Get the IDs of the users in the current group. None will be returned if there is no group.
  pub fn get_user_ids(&self) -> Option<Vec<u64>> {
    self.group.as_ref().map(|group| {
      group
        .members()
        .map(|member| {
          u64::from_be_bytes(
            member
              .credential
              .serialized_content()
              .try_into()
              .unwrap_or([0, 0, 0, 0, 0, 0, 0, 0]),
          )
        })
        .collect()
    })
  }

  /// Check whether a user's key ratchet is in passthrough mode
  pub fn can_passthrough(&self, user_id: u64) -> bool {
    let Some(decryptor) = self.decryptors.get(&user_id) else {
      return false;
    };

    decryptor.can_passthrough()
  }

  /// Set whether passthrough mode is enabled on all decryptors. The transition expiry (in seconds) when disabling passthrough mode defaults to 10 seconds
  pub fn set_passthrough_mode(&mut self, passthrough_mode: bool, transition_expiry: Option<u32>) {
    for (_, decryptor) in self.decryptors.iter_mut() {
      decryptor
        .transition_to_passthrough_mode(passthrough_mode, transition_expiry.unwrap_or(10) as usize);
    }
  }
}

impl Debug for DaveSession {
  fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
    f.debug_struct("DaveSession")
      .field("protocol_version", &self.protocol_version)
      .field("user_id", &self.user_id())
      .field("channel_id", &self.channel_id())
      .field("is_ready", &self.is_ready)
      .field("status", &self.status)
      .finish()
  }
}
