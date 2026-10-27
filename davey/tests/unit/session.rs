//! Ported from libdave
//! [`cpp/test/mls_session_tests.cpp`](https://github.com/discord/libdave/blob/8de72b1f8a2ac3c5a5270755bb8091a62e3c6169/cpp/test/mls_session_tests.cpp)

use std::{collections::HashSet, num::NonZeroU16};

use openmls::prelude::{tls_codec::Serialize, *};
use openmls_basic_credential::SignatureKeyPair;
use openmls_rust_crypto::OpenMlsRustCrypto;

use crate::{
  CommitWelcome, DaveSession, ProposalsOperationType,
  errors::{
    ProcessCommitError, ProcessProposalsError, ProcessWelcomeError, SetExternalSenderError,
  },
};

const TEST_PROTOCOL_VERSION: NonZeroU16 = NonZeroU16::new(1).unwrap();
const TEST_GROUP_ID: u64 = 1234567890;
const OTHER_GROUP_ID: u64 = 9876543210;

const USER_A: u64 = 1234123412341234;
const USER_B: u64 = 5678567856785678;
const USER_C: u64 = 9012901290129012;
const USER_D: u64 = 3456345634563456;

/// Plays the role of the voice gateway's external sender.
///
/// libdave: `ExternalSender` in
/// [`cpp/test/external_sender.cpp`](https://github.com/discord/libdave/blob/8de72b1f8a2ac3c5a5270755bb8091a62e3c6169/cpp/test/external_sender.cpp)
struct TestExternalSender {
  provider: OpenMlsRustCrypto,
  group_id: GroupId,
  signer: SignatureKeyPair,
  external_sender: ExternalSender,
}

impl TestExternalSender {
  fn new(group_id: u64) -> Self {
    let ciphersuite = Ciphersuite::MLS_128_DHKEMP256_AES128GCM_SHA256_P256;
    let signer = SignatureKeyPair::new(ciphersuite.signature_algorithm()).unwrap();
    let external_sender = ExternalSender::new(
      signer.public().into(),
      BasicCredential::new(vec![0x00, 0x01, 0x01, 0x00]).into(),
    );

    Self {
      provider: OpenMlsRustCrypto::default(),
      group_id: GroupId::from_slice(&group_id.to_be_bytes()),
      signer,
      external_sender,
    }
  }

  fn marshalled_external_sender(&self) -> Vec<u8> {
    self.external_sender.tls_serialize_detached().unwrap()
  }

  /// Returns the payload of an append [dave_mls_proposals (27)](https://daveprotocol.com/#dave_mls_proposals-27)
  /// message proposing to add the owner of `key_package`.
  fn propose_add(&self, epoch: u64, key_package: &[u8]) -> Vec<u8> {
    let key_package = KeyPackageIn::tls_deserialize_exact_bytes(key_package)
      .unwrap()
      .validate(self.provider.crypto(), ProtocolVersion::Mls10)
      .unwrap();

    let message = ExternalProposal::new_add::<OpenMlsRustCrypto>(
      key_package,
      self.group_id.clone(),
      GroupEpoch::from(epoch),
      &self.signer,
      SenderExtensionIndex::new(0),
    )
    .unwrap();

    VLBytes::new(message.tls_serialize_detached().unwrap())
      .tls_serialize_detached()
      .unwrap()
  }
}

/// libdave: `TestSession::InitAndSetExternalSender` in
/// [`cpp/test/mls_session_tests.cpp`](https://github.com/discord/libdave/blob/8de72b1f8a2ac3c5a5270755bb8091a62e3c6169/cpp/test/mls_session_tests.cpp#L44-L48)
fn init_and_set_external_sender(
  user_id: u64,
  external_sender: &TestExternalSender,
  group_id: u64,
) -> DaveSession {
  let mut session = DaveSession::new(TEST_PROTOCOL_VERSION, user_id, group_id, None).unwrap();
  session
    .set_external_sender(&external_sender.marshalled_external_sender())
    .unwrap();
  session
}

/// [`cpp/test/mls_session_tests.cpp`](https://github.com/discord/libdave/blob/8de72b1f8a2ac3c5a5270755bb8091a62e3c6169/cpp/test/mls_session_tests.cpp#L71-L89)
fn propose_add_and_commit(
  external_sender: &TestExternalSender,
  creator: &mut DaveSession,
  joiner: &mut DaveSession,
) -> CommitWelcome {
  let key_package = joiner.create_key_package().unwrap();
  let proposal = external_sender.propose_add(0, &key_package);

  creator
    .process_proposals(
      ProposalsOperationType::APPEND,
      &proposal,
      Some(&[creator.user_id(), joiner.user_id()]),
    )
    .unwrap()
    .expect("a commit should be produced")
}

/// [`cpp/test/mls_session_tests.cpp`](https://github.com/discord/libdave/blob/6396c90a/cpp/test/mls_session_tests.cpp#L94-L109)
fn establish_group(
  external_sender: &TestExternalSender,
  creator: &mut DaveSession,
  joiner: &mut DaveSession,
) {
  let commit_welcome = propose_add_and_commit(external_sender, creator, joiner);
  assert!(creator.process_commit(&commit_welcome.commit).unwrap());
  joiner
    .process_welcome(
      &commit_welcome
        .welcome
        .expect("a welcome should be produced"),
      Some(&[creator.user_id(), joiner.user_id()]),
    )
    .unwrap();
}

/// [`cpp/test/mls_session_tests.cpp`](https://github.com/discord/libdave/blob/6396c90a/cpp/test/mls_session_tests.cpp#L113-L124)
fn prepare_commit(
  committer: &mut DaveSession,
  proposals: &[u8],
  recognized_user_ids: &[u64],
) -> Vec<u8> {
  committer
    .process_proposals(
      ProposalsOperationType::APPEND,
      proposals,
      Some(recognized_user_ids),
    )
    .unwrap()
    .expect("a commit should be produced")
    .commit
}

/// libdave: [`MlsSessionTests.SessionJoinViaCommitAndWelcome`](https://github.com/discord/libdave/blob/8de72b1f8a2ac3c5a5270755bb8091a62e3c6169/cpp/test/mls_session_tests.cpp#L95)
#[test]
fn join_via_commit_and_welcome() {
  let external_sender = TestExternalSender::new(TEST_GROUP_ID);
  let mut a = init_and_set_external_sender(USER_A, &external_sender, TEST_GROUP_ID);
  let mut b = init_and_set_external_sender(USER_B, &external_sender, TEST_GROUP_ID);

  let commit_welcome = propose_add_and_commit(&external_sender, &mut a, &mut b);

  // the creator processes its own group-initialization commit
  assert!(a.process_commit(&commit_welcome.commit).unwrap());
  assert_eq!(a.get_user_ids().unwrap().len(), 2);

  b.process_welcome(
    &commit_welcome
      .welcome
      .expect("a welcome should be produced"),
    Some(&[USER_A, USER_B]),
  )
  .unwrap();
  assert_eq!(b.get_user_ids().unwrap().len(), 2);

  let authenticator_a = a.get_epoch_authenticator().unwrap().as_slice();
  let authenticator_b = b.get_epoch_authenticator().unwrap().as_slice();
  assert!(!authenticator_a.is_empty());
  assert_eq!(authenticator_a, authenticator_b);
}

/// libdave: [`MlsSessionTests.SessionWelcomeRejectsUnrecognizedRosterUser`](https://github.com/discord/libdave/blob/8de72b1f8a2ac3c5a5270755bb8091a62e3c6169/cpp/test/mls_session_tests.cpp#L122)
#[test]
fn welcome_rejects_unrecognized_roster_user() {
  let external_sender = TestExternalSender::new(TEST_GROUP_ID);
  let mut a = init_and_set_external_sender(USER_A, &external_sender, TEST_GROUP_ID);
  let mut b = init_and_set_external_sender(USER_B, &external_sender, TEST_GROUP_ID);

  let commit_welcome = propose_add_and_commit(&external_sender, &mut a, &mut b);

  // the welcomed group's roster includes user A, which b does not recognize
  // libdave: "Welcome message lists unrecognized user ID"
  assert!(matches!(
    b.process_welcome(&commit_welcome.welcome.unwrap(), Some(&[USER_B])),
    Err(ProcessWelcomeError::UnrecognizedUser(USER_A))
  ));
}

/// libdave: [`MlsSessionTests.SessionWelcomeRejectsMismatchedGroupId`](https://github.com/discord/libdave/blob/8de72b1f8a2ac3c5a5270755bb8091a62e3c6169/cpp/test/mls_session_tests.cpp#L139)
#[test]
fn welcome_rejects_mismatched_group_id() {
  let external_sender = TestExternalSender::new(TEST_GROUP_ID);
  let mut a = init_and_set_external_sender(USER_A, &external_sender, TEST_GROUP_ID);

  // b was initialized for a different group than the welcome is for
  let mut b = init_and_set_external_sender(USER_B, &external_sender, OTHER_GROUP_ID);

  let commit_welcome = propose_add_and_commit(&external_sender, &mut a, &mut b);

  // libdave: "Unexpected group ID in Welcome"
  assert!(matches!(
    b.process_welcome(&commit_welcome.welcome.unwrap(), Some(&[USER_A, USER_B])),
    Err(ProcessWelcomeError::UnexpectedGroupId)
  ));
}

/// libdave: [`MlsSessionTests.SessionCommitBeforeWelcomeIsRejected`](https://github.com/discord/libdave/blob/8de72b1f8a2ac3c5a5270755bb8091a62e3c6169/cpp/test/mls_session_tests.cpp#L157)
#[test]
fn commit_before_welcome_is_rejected() {
  let external_sender = TestExternalSender::new(TEST_GROUP_ID);
  let mut a = init_and_set_external_sender(USER_A, &external_sender, TEST_GROUP_ID);
  let mut b = init_and_set_external_sender(USER_B, &external_sender, TEST_GROUP_ID);
  let mut c = init_and_set_external_sender(USER_C, &external_sender, TEST_GROUP_ID);

  // a prepares the winning group-initialization commit (adding b)
  let commit_welcome_a = propose_add_and_commit(&external_sender, &mut a, &mut b);

  // b also processed proposals for its own pending group (adding c), so it
  // has a prepared commit of its own that does not match a's
  propose_add_and_commit(&external_sender, &mut b, &mut c);

  // b has not been welcomed into any group, so a's commit must be rejected
  // rather than applied to b's unrelated pending group
  // libdave: "Unexpected commit before welcome"
  assert!(matches!(
    b.process_commit(&commit_welcome_a.commit),
    Err(ProcessCommitError::CommitBeforeWelcome)
  ));
}

/// libdave: [`MlsSessionTests.SessionOwnCommitMustMatchPreparedCommit`](https://github.com/discord/libdave/blob/6396c90a/cpp/test/mls_session_tests.cpp#L218)
#[test]
fn own_commit_must_match_prepared_commit() {
  let external_sender = TestExternalSender::new(TEST_GROUP_ID);
  let mut a = init_and_set_external_sender(USER_A, &external_sender, TEST_GROUP_ID);
  let mut b = init_and_set_external_sender(USER_B, &external_sender, TEST_GROUP_ID);
  let mut c = init_and_set_external_sender(USER_C, &external_sender, TEST_GROUP_ID);
  let mut d = init_and_set_external_sender(USER_D, &external_sender, TEST_GROUP_ID);

  establish_group(&external_sender, &mut a, &mut b);

  let propose_add_c = external_sender.propose_add(1, &c.create_key_package().unwrap());
  let first_commit = prepare_commit(&mut a, &propose_add_c, &[USER_A, USER_B, USER_C]);

  // a second commit for the same epoch replaces a's pending commit
  let propose_add_d = external_sender.propose_add(1, &d.create_key_package().unwrap());
  let second_commit = prepare_commit(&mut a, &propose_add_d, &[USER_A, USER_B, USER_C, USER_D]);
  assert_ne!(first_commit, second_commit);

  b.process_proposals(
    ProposalsOperationType::APPEND,
    &propose_add_c,
    Some(&[USER_A, USER_B, USER_C]),
  )
  .unwrap()
  .expect("a commit should be produced");
  assert!(b.process_commit(&first_commit).unwrap());
  let user_ids_b: HashSet<u64> = b.get_user_ids().unwrap().into_iter().collect();
  assert_eq!(user_ids_b, HashSet::from([USER_A, USER_B, USER_C]));

  // a's pending commit has the group, epoch and leaf index the first commit would produce, but
  // it is the result of the second commit
  // libdave: "Handle own commits with caching"
  assert!(matches!(
    a.process_commit(&first_commit),
    Err(ProcessCommitError::OwnCommitMismatch)
  ));
}

/// libdave: [`MlsSessionTests.SessionOwnLatestPreparedCommitUsesCachedState`](https://github.com/discord/libdave/blob/6396c90a/cpp/test/mls_session_tests.cpp#L258)
#[test]
fn own_latest_prepared_commit_uses_cached_state() {
  let external_sender = TestExternalSender::new(TEST_GROUP_ID);
  let mut a = init_and_set_external_sender(USER_A, &external_sender, TEST_GROUP_ID);
  let mut b = init_and_set_external_sender(USER_B, &external_sender, TEST_GROUP_ID);
  let mut c = init_and_set_external_sender(USER_C, &external_sender, TEST_GROUP_ID);
  let mut d = init_and_set_external_sender(USER_D, &external_sender, TEST_GROUP_ID);

  establish_group(&external_sender, &mut a, &mut b);

  let propose_add_c = external_sender.propose_add(1, &c.create_key_package().unwrap());
  prepare_commit(&mut a, &propose_add_c, &[USER_A, USER_B, USER_C]);

  let propose_add_d = external_sender.propose_add(1, &d.create_key_package().unwrap());
  let second_commit = prepare_commit(&mut a, &propose_add_d, &[USER_A, USER_B, USER_C, USER_D]);

  b.process_proposals(
    ProposalsOperationType::APPEND,
    &propose_add_c,
    Some(&[USER_A, USER_B, USER_C]),
  )
  .unwrap()
  .expect("a commit should be produced");
  b.process_proposals(
    ProposalsOperationType::APPEND,
    &propose_add_d,
    Some(&[USER_A, USER_B, USER_C, USER_D]),
  )
  .unwrap()
  .expect("a commit should be produced");
  assert!(b.process_commit(&second_commit).unwrap());
  let user_ids_b: HashSet<u64> = b.get_user_ids().unwrap().into_iter().collect();
  assert_eq!(user_ids_b, HashSet::from([USER_A, USER_B, USER_C, USER_D]));

  assert!(a.process_commit(&second_commit).unwrap());
  let user_ids_a: HashSet<u64> = a.get_user_ids().unwrap().into_iter().collect();
  assert_eq!(user_ids_a, user_ids_b);

  let authenticator_a = a.get_epoch_authenticator().unwrap().as_slice();
  assert!(!authenticator_a.is_empty());
  assert_eq!(
    authenticator_a,
    b.get_epoch_authenticator().unwrap().as_slice()
  );
}

/// libdave: [`MlsSessionTests.SessionCommitWithoutQueuedProposalsFails`](https://github.com/discord/libdave/blob/8de72b1f8a2ac3c5a5270755bb8091a62e3c6169/cpp/test/mls_session_tests.cpp#L183)
#[test]
fn commit_without_queued_proposals_fails() {
  let external_sender = TestExternalSender::new(TEST_GROUP_ID);
  let mut a = init_and_set_external_sender(USER_A, &external_sender, TEST_GROUP_ID);
  let mut b = init_and_set_external_sender(USER_B, &external_sender, TEST_GROUP_ID);

  let commit_welcome = propose_add_and_commit(&external_sender, &mut a, &mut b);

  assert!(a.process_commit(&commit_welcome.commit).unwrap());

  // a is in an established group with no queued proposals; a replayed commit
  // is a hard failure that should request a reset, not a silent ignore
  // libdave: "ProcessCommit called without queued proposals"
  assert!(matches!(
    a.process_commit(&commit_welcome.commit),
    Err(ProcessCommitError::NoQueuedProposals)
  ));
}

/// libdave: [`MlsSessionTests.SessionCommitWithoutAnyStateIsIgnored`](https://github.com/discord/libdave/blob/8de72b1f8a2ac3c5a5270755bb8091a62e3c6169/cpp/test/mls_session_tests.cpp#L204)
#[test]
fn commit_without_any_state_is_ignored() {
  let external_sender = TestExternalSender::new(TEST_GROUP_ID);
  let mut a = init_and_set_external_sender(USER_A, &external_sender, TEST_GROUP_ID);
  let mut b = init_and_set_external_sender(USER_B, &external_sender, TEST_GROUP_ID);

  let commit_welcome = propose_add_and_commit(&external_sender, &mut a, &mut b);

  // a session with no pending or established state ignores in-flight commits
  // (e.g. during a reset) instead of failing and causing thrashing
  let mut fresh = DaveSession::new(TEST_PROTOCOL_VERSION, USER_C, TEST_GROUP_ID, None).unwrap();
  assert!(!fresh.process_commit(&commit_welcome.commit).unwrap());
}

/// libdave: [`MlsSessionTests.SessionSetExternalSenderAfterJoinReportsError`](https://github.com/discord/libdave/blob/8de72b1f8a2ac3c5a5270755bb8091a62e3c6169/cpp/test/mls_session_tests.cpp#L223)
#[test]
fn set_external_sender_after_join_reports_error() {
  let external_sender = TestExternalSender::new(TEST_GROUP_ID);
  let mut a = init_and_set_external_sender(USER_A, &external_sender, TEST_GROUP_ID);
  let mut b = init_and_set_external_sender(USER_B, &external_sender, TEST_GROUP_ID);

  let commit_welcome = propose_add_and_commit(&external_sender, &mut a, &mut b);

  assert!(a.process_commit(&commit_welcome.commit).unwrap());

  assert!(matches!(
    a.set_external_sender(&external_sender.marshalled_external_sender()),
    Err(SetExternalSenderError::AlreadyInGroup)
  ));
}

/// libdave: [`MlsSessionTests.SessionProposalsWithoutStateReportsError`](https://github.com/discord/libdave/blob/8de72b1f8a2ac3c5a5270755bb8091a62e3c6169/cpp/test/mls_session_tests.cpp#L250)
#[test]
fn proposals_without_state_reports_error() {
  let mut session = DaveSession::new(TEST_PROTOCOL_VERSION, USER_A, TEST_GROUP_ID, None).unwrap();
  assert!(matches!(
    session.process_proposals(ProposalsOperationType::APPEND, &[], None),
    Err(ProcessProposalsError::NoGroup)
  ));
}
