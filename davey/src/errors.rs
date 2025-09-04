use std::{array::TryFromSliceError, num::NonZeroU16};

use openmls::{
  framing::errors::ProtocolMessageError,
  group::{
    CommitToPendingProposalsError, ExportSecretError, MergeCommitError, MergePendingCommitError,
    NewGroupError, ProcessMessageError, RemoveProposalError, WelcomeError,
  },
  prelude::{CryptoError, InvalidExtensionError, KeyPackageNewError, tls_codec},
};
use openmls_rust_crypto::MemoryStorageError;
use thiserror::Error;

use crate::{cryptor::MediaType, displayable_code::MAX_GROUP_SIZE, session::DAVE_PROTOCOL_VERSION};

#[derive(Error, Debug)]
pub enum DisplayableCodeError {
  #[error("data length less than desired length")]
  DataLessThanDesiredLength,
  #[error("desired length is not a multiple of group size")]
  DesiredLengthNotMultipleOfGroupSize,
  #[error("group size must be less than or equal to {MAX_GROUP_SIZE}")]
  GroupSizeGreaterThanMaxGroupSize,
  #[error("attempted to access out of bounds for data")]
  OutOfBoundsDataIndex,
}

#[derive(Error, Debug)]
pub enum GenerateKeyFingerprintError {
  #[error("unsupported fingerprint format version")]
  UnsupportedFormatVersion,
  #[error("key is empty")]
  KeyIsEmpty,
}

#[derive(Error, Debug)]
pub enum GeneratePairwiseFingerprintError {
  #[error("failed to generate key fingerprint: {0}")]
  GenerateKeyFingerprint(#[from] GenerateKeyFingerprintError),
  #[error("failed to hash fingerprints: {0}")]
  HashingFailed(scrypt::errors::InvalidOutputLen),
}

#[derive(Error, Debug)]
#[error(
  "an unsupported protocol version was provided, should be no greater than {DAVE_PROTOCOL_VERSION}"
)]
pub struct UnsupportedProtocolVersion(pub NonZeroU16);

#[derive(Error, Debug)]
pub enum InitError {
  #[error("{0}")]
  UnsupportedProtocolVersion(#[from] UnsupportedProtocolVersion),
  #[error("failed to generate key pair: {0}")]
  KeyPairGenerationFailed(#[from] CryptoError),
}

#[derive(Error, Debug)]
pub enum ReinitError {
  #[error("{0}")]
  Init(#[from] InitError),
  #[error("{0}")]
  Reset(#[from] ResetError),
  #[error("{0}")]
  PendingGroup(#[from] PendingGroupError),
}

#[derive(Error, Debug)]
pub enum ResetError {
  #[error("failed to delete group: {0}")]
  DeletingGroupFailed(#[from] MemoryStorageError),
}

#[derive(Error, Debug)]
pub enum SetExternalSenderError {
  #[error("cannot set an external sender when already in a group")]
  AlreadyInGroup,
  #[error("failed to delete group: {0}")]
  DeletingGroupFailed(#[from] MemoryStorageError),
  #[error("failed to deserialize message: {0}")]
  DeserializeExternalSender(#[from] tls_codec::Error),
  #[error("{0}")]
  PendingGroup(#[from] PendingGroupError),
}

#[derive(Error, Debug)]
#[error("failed to create key package: {0}")]
pub struct CreateKeyPackageError(#[from] KeyPackageNewError);

#[derive(Error, Debug)]
pub enum PendingGroupError {
  #[error("cannot create pending group without external sender")]
  NoExternalSender,
  #[error("failed to add external sender to group: {0}")]
  AddingExternalSenderFailed(#[from] InvalidExtensionError),
  #[error("failed to create group: {0}")]
  CreatingGroupFailed(#[from] NewGroupError<MemoryStorageError>),
}

#[derive(Error, Debug)]
pub enum ProcessProposalsError {
  #[error("cannot process proposals without a group")]
  NoGroup,
  #[error("failed to deserialize proposal: {0}")]
  DeserializeProposalFailed(tls_codec::Error),
  #[error("failed to deserialize message: {0}")]
  DeserializeMessageFailed(tls_codec::Error),
  #[error("message was not a private or public message: {0}")]
  MessageNotPrivateOrPublic(#[from] ProtocolMessageError),
  #[error("failed to process message: {0}")]
  MessageProcessingFailed(#[from] ProcessMessageError),
  #[error("failed to convert credential content to user id: {0}")]
  CredentialContentConvertFailed(TryFromSliceError),
  #[error("unexpected user in add proposal: {0}")]
  UnexpectedUser(u64),
  #[error("failed to store pending proposal: {0}")]
  StorePendingProposalFailed(MemoryStorageError),
  #[error("processed message was not a proposal")]
  MessageNotProposal,
  #[error("failed to deserialize proposal ref: {0}")]
  DeserializeProposalRefFailed(tls_codec::Error),
  #[error("failed to remove pending proposal: {0}")]
  RemovingPendingProposalFailed(#[from] RemoveProposalError<MemoryStorageError>),
  #[error("failed to clear pending commit: {0}")]
  RemovingPendingCommitFailed(MemoryStorageError),
  #[error("failed to commit to pending proposals: {0}")]
  CommitToPendingProposalsFailed(CommitToPendingProposalsError<MemoryStorageError>),
}

#[derive(Error, Debug)]
pub enum ProcessWelcomeError {
  #[error("cannot process welcome when already in a group")]
  AlreadyInGroup,
  #[error("cannot process welcome without an external sender")]
  NoExternalSender,
  #[error("failed to deserialize welcome: {0}")]
  DeserializeWelcomeFailed(#[from] tls_codec::Error),
  #[error("failed to create staged welcome: {0}")]
  CreatingStagedWelcomeFailed(#[from] WelcomeError<MemoryStorageError>),
  #[error("expected external senders extension in welcome")]
  ExpectedExternalSenderExtension,
  #[error("expected only one external sender in welcome")]
  ExpectedOneExternalSender,
  #[error("expected same external sender in welcome as currently set")]
  UnexpectedExternalSender,
  #[error("failed to delete pending group: {0}")]
  DeletingPendingGroupFailed(MemoryStorageError),
  #[error("failed to update ratchets: {0}")]
  UpdatingRatchetsFailed(#[from] UpdateRatchetsError),
}

#[derive(Error, Debug)]
pub enum ProcessCommitError {
  #[error("cannot process commit without a group")]
  NoGroup,
  #[error("cannot process commit for a pending group")]
  PendingGroup,
  #[error("failed to deserialize message: {0}")]
  DeserializeMessage(tls_codec::Error),
  #[error("message was not a private or public message: {0}")]
  MessageNotPrivateOrPublic(#[from] ProtocolMessageError),
  #[error("message was for a different group")]
  MessageForDifferentGroup,
  #[error("failed to merge pending commit: {0}")]
  MergingPendingCommitFailed(#[from] MergePendingCommitError<MemoryStorageError>),
  #[error("failed to merge staged commit: {0}")]
  MergingStagedCommitFailed(#[from] MergeCommitError<MemoryStorageError>),
  #[error("failed to merge staged commit: {0}")]
  ProcessingMessageFailed(#[from] ProcessMessageError),
  #[error("processed message was not a staged commit")]
  ProcessedMessageNotStagedCommit,
  #[error("failed to update ratchets: {0}")]
  UpdatingRatchetsFailed(#[from] UpdateRatchetsError),
}

#[derive(Error, Debug)]
pub enum GetVerificationCodeError {
  #[error("{0}")]
  GettingPairwiseFingerprint(#[from] GetPairwiseFingerprintError),
  #[error("{0}")]
  GeneratingPairwiseFingerprint(#[from] GeneratePairwiseFingerprintError),
  #[error("{0}")]
  GeneratingDisplayableCode(#[from] DisplayableCodeError),
}

#[derive(Error, Debug)]
pub enum GetPairwiseFingerprintError {
  #[error("cannot get pairwise fingerprint without an established group")]
  NoEstablishedGroup,
  #[error("user is not a member of the group")]
  UserNotInGroup,
  #[error("error while generating pairwise fingerprint: {0}")]
  GeneratingPairwiseFingerprint(#[from] GeneratePairwiseFingerprintError),
  #[error("error while generating key fingerprint: {0}")]
  GeneratingKeyFingerprint(#[from] GenerateKeyFingerprintError),
}

#[derive(Error, Debug)]
pub enum UpdateRatchetsError {
  #[error("cannot get pairwise fingerprint without an established group")]
  NoEstablishedGroup,
  #[error("failed to export secret from group: {0}")]
  ExportingSecretFailed(#[from] ExportSecretError),
  #[error("error while generating displayable code: {0}")]
  GeneratingDisplayableCode(#[from] DisplayableCodeError),
}

#[derive(Error, Debug)]
pub enum EncryptError {
  #[error("session is not ready to encrypt packets")]
  NotReady,
  #[error("failed to encrypt packet")]
  EncryptionFailed,
}

#[derive(Error, Debug)]
pub enum DecryptError {
  #[error("user has no decryptor")]
  NoDecryptorForUser,
  #[error("failed to decrypt packet")]
  DecryptionFailed(#[from] DecryptorDecryptError),
}

#[derive(Error, Debug)]
#[error("user has no decryptor")]
pub struct NoDecryptorForUser;

#[derive(Error, Debug)]
pub enum DecryptorDecryptError {
  #[error("provided frame was unencrypted when passthrough mode was disabled")]
  UnencryptedWhenPassthroughDisabled,
  #[error(
    "no valid cryptor manager could be found for {media_type:?}, encrypted size: {encrypted_size}, plaintext size: {plaintext_size}, num of managers: {manager_count})"
  )]
  NoValidCryptorFound {
    media_type: MediaType,
    encrypted_size: usize,
    plaintext_size: usize,
    manager_count: usize,
  },
}

#[derive(Debug, Error)]
pub enum ExpiringCipherError {
  #[error("failed to get key: {0}")]
  GetKey(#[from] GetKeyError),
  #[error("failed to create cipher: {0}")]
  CreatingCipherFailed(#[from] crate::aes_gcm::aes::cipher::InvalidLength),
}

#[derive(Error, Debug)]
#[error("frame is too small to contain the encrypted frame")]
pub struct FrameTooSmall;

#[derive(Error, Debug)]
#[error("invalid length when expanding HKDF")]
pub struct InvalidLength;

#[derive(Error, Debug)]
pub enum GetKeyError {
  #[error("attempted to get a key that already expired")]
  KeyExpired,
  #[error("failed to get next generation ({0}): {1}")]
  NextGenerationFailed(u32, InvalidLength),
}
