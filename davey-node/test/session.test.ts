import test, { SkipFn, TestFn } from 'ava';

import { DAVESession, MediaType, ProposalsOperationType, SessionStatus, DEBUG_BUILD } from '../index';

// These buffers are from a session in the channel 927310423890473011, as the user 158049329150427136 (Snazzah)
// where the proposal is adding the user 158533742254751744

const EXTERNAL_SENDER = Buffer.from([
  /* 0x00, 0x04, 0x19, */ 0x40, 0x41, 0x04, 0xca, 0x1a, 0x2b, 0x10, 0x25, 0x01, 0xd0, 0x67, 0x2b, 0xd4, 0x5e, 0xd7,
  0x4f, 0xfb, 0x83, 0xe0, 0x78, 0xb2, 0xba, 0x5b, 0x12, 0xc3, 0xf6, 0x9f, 0xad, 0x56, 0xf0, 0x83, 0xb6, 0xa3, 0x5f,
  0xc9, 0x89, 0xc6, 0x73, 0x6b, 0x58, 0x52, 0xb5, 0xae, 0xcd, 0xfc, 0xdf, 0x20, 0x6e, 0x15, 0x6d, 0x3d, 0x1d, 0xba,
  0x8e, 0x3e, 0x5b, 0x2f, 0x89, 0xfc, 0x0c, 0x16, 0xf1, 0x16, 0x14, 0xe8, 0x4e, 0x4a, 0x00, 0x01, 0x01, 0x00,
]);

const APPENDING_PROPOSALS = Buffer.from([
  0x41, 0xf0, 0x00, 0x01, 0x00, 0x01, 0x08, 0x0c, 0xde, 0x77, 0xea, 0xdc, 0x82, 0x30, 0x33, 0x00, 0x00, 0x00, 0x00,
  0x00, 0x00, 0x00, 0x00, 0x02, 0x00, 0x00, 0x00, 0x00, 0x00, 0x02, 0x00, 0x01, 0x00, 0x01, 0x00, 0x02, 0x40, 0x41,
  0x04, 0xa6, 0x1a, 0xcd, 0x34, 0xff, 0x05, 0x48, 0xe6, 0xf7, 0x67, 0xcc, 0x4d, 0xf9, 0x61, 0x9b, 0x51, 0xba, 0x58,
  0x14, 0xd5, 0x2e, 0xe5, 0x58, 0x28, 0x4f, 0xc5, 0x54, 0x40, 0x57, 0x68, 0xe9, 0xe7, 0x41, 0xba, 0x32, 0x27, 0x64,
  0x14, 0x94, 0x1b, 0x7c, 0x01, 0x90, 0xdc, 0xb5, 0xdf, 0xc3, 0x34, 0x9a, 0x16, 0x8f, 0x12, 0x47, 0xec, 0xbd, 0xf6,
  0xfc, 0x69, 0xf3, 0xee, 0xca, 0xb3, 0x76, 0x5d, 0x40, 0x41, 0x04, 0xf4, 0x4d, 0xa2, 0x4e, 0x5a, 0xa9, 0xf7, 0x37,
  0x96, 0xfa, 0x38, 0xbe, 0x11, 0x55, 0x56, 0xe6, 0xb7, 0xd4, 0xf6, 0xba, 0x55, 0xd2, 0xec, 0xc3, 0xf1, 0xb9, 0xd1,
  0x98, 0xaf, 0x62, 0x37, 0xe3, 0xfc, 0x8f, 0xc6, 0x35, 0x99, 0x6b, 0x6c, 0x76, 0xe7, 0x7b, 0x4a, 0xca, 0xce, 0x33,
  0xf5, 0xcf, 0xd7, 0x45, 0xad, 0x0d, 0x54, 0x0d, 0xd6, 0xf0, 0x3f, 0x0d, 0xa8, 0x5c, 0x82, 0xe1, 0x47, 0x14, 0x40,
  0x41, 0x04, 0xe7, 0x79, 0x39, 0x85, 0xed, 0x07, 0x4a, 0xf4, 0x95, 0x68, 0xb5, 0x3c, 0xf2, 0xe3, 0x97, 0x46, 0x88,
  0x27, 0x9f, 0x02, 0xee, 0x8d, 0x7c, 0x7d, 0xf0, 0x99, 0xce, 0x3c, 0x7a, 0x1a, 0x28, 0xe7, 0x47, 0xf5, 0x9a, 0x7c,
  0x7c, 0x23, 0xe9, 0xef, 0x4f, 0x78, 0x15, 0xfb, 0x34, 0x69, 0xf3, 0x9e, 0xa1, 0x24, 0xf8, 0xb7, 0x67, 0x12, 0xc4,
  0x1b, 0x76, 0x3a, 0x55, 0xb8, 0x67, 0xe6, 0xb4, 0x8b, 0x00, 0x01, 0x08, 0x02, 0x33, 0x39, 0x99, 0x40, 0x02, 0x00,
  0x00, 0x02, 0x00, 0x01, 0x02, 0x00, 0x02, 0x00, 0x00, 0x02, 0x00, 0x01, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
  0x00, 0x00, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0x00, 0x40, 0x48, 0x30, 0x46, 0x02, 0x21, 0x00, 0xd8,
  0x74, 0xdc, 0x77, 0x7d, 0x4e, 0xde, 0x7e, 0x6d, 0x33, 0x74, 0xf7, 0x37, 0xbc, 0x13, 0x94, 0xac, 0x0f, 0xfd, 0x06,
  0x35, 0xab, 0xdc, 0x9d, 0x02, 0xb3, 0xe3, 0x59, 0xe0, 0x59, 0x46, 0x6a, 0x02, 0x21, 0x00, 0xe6, 0x2e, 0x97, 0xae,
  0xfd, 0x5c, 0x6b, 0x32, 0xff, 0x0a, 0xc5, 0xc5, 0x15, 0x9d, 0xbe, 0x94, 0xf6, 0xf5, 0xa0, 0x1b, 0xd0, 0xdd, 0x14,
  0xa9, 0xdc, 0xc4, 0xd1, 0xe6, 0x24, 0x89, 0x72, 0xac, 0x00, 0x40, 0x47, 0x30, 0x45, 0x02, 0x20, 0x51, 0x68, 0xab,
  0xdf, 0x8d, 0x83, 0xa4, 0x8d, 0xaf, 0x8d, 0x59, 0x60, 0xaf, 0xb3, 0x05, 0x02, 0x2d, 0xe7, 0x07, 0xc7, 0x49, 0x60,
  0x87, 0xfe, 0xb4, 0x30, 0x04, 0xc9, 0xfd, 0x2b, 0xe5, 0xe8, 0x02, 0x21, 0x00, 0x83, 0x12, 0xa6, 0xf6, 0xdf, 0x1f,
  0xf5, 0x93, 0x67, 0x1a, 0x39, 0xf9, 0x96, 0x6f, 0x6d, 0x1c, 0xae, 0xf4, 0x3e, 0x0c, 0x6d, 0x53, 0xc7, 0x43, 0x00,
  0xba, 0x08, 0x9c, 0xee, 0xec, 0xfb, 0xf4, 0x40, 0x47, 0x30, 0x45, 0x02, 0x21, 0x00, 0xcd, 0xbe, 0x80, 0x4b, 0xa0,
  0x6a, 0x9b, 0xe1, 0x76, 0x15, 0xfe, 0x3c, 0x7f, 0x90, 0x55, 0xf3, 0x1a, 0x6d, 0x0e, 0xa9, 0x40, 0x2d, 0xd9, 0xfd,
  0xa6, 0xd1, 0x09, 0xe9, 0xa3, 0xcb, 0x63, 0x2b, 0x02, 0x20, 0x67, 0x40, 0x9e, 0x59, 0xf6, 0xb7, 0xf0, 0xa3, 0xed,
  0xdd, 0x33, 0x0a, 0x09, 0x2a, 0x6c, 0x13, 0xd9, 0x9d, 0x12, 0xab, 0xae, 0xbe, 0x0d, 0x6d, 0x40, 0xa0, 0xda, 0xe4,
  0x35, 0xc2, 0xa7, 0xa2,
]);

const REVOKING_PROPOSALS = Buffer.from([
  0x21, 0x20, 0x62, 0x38, 0x6f, 0xfb, 0x20, 0xb2, 0x8f, 0x55, 0x6b, 0x24, 0x65, 0xc0, 0xa2, 0x52, 0x0b, 0xa2, 0xb0,
  0x74, 0xfc, 0xa0, 0x0e, 0x94, 0xb2, 0xfd, 0xeb, 0xc0, 0x49, 0x6d, 0x54, 0x4c, 0xd6, 0xc0,
]);

const EMPTY_BUFFER = Buffer.alloc(0);

const SILENCE_FRAME = Buffer.from([0xf8, 0xff, 0xfe]);

const CHANNEL_ID = '927310423890473011';
const MY_USER_ID = '158049329150427136';
const OTHER_USER_ID = '158533742254751744';

const createSession = (status: SessionStatus = SessionStatus.INACTIVE) => {
  const session = new DAVESession(1, MY_USER_ID, CHANNEL_ID);

  switch (status) {
    case SessionStatus.INACTIVE:
      break;
    case SessionStatus.PENDING:
      session.setExternalSender(EXTERNAL_SENDER);
      session.getSerializedKeyPackage();
      break;
    case SessionStatus.AWAITING_RESPONSE:
      session.setExternalSender(EXTERNAL_SENDER);
      session.getSerializedKeyPackage();
      session.processProposals(ProposalsOperationType.APPEND, APPENDING_PROPOSALS);
      break;
    case SessionStatus.ACTIVE:
      session.setExternalSender(EXTERNAL_SENDER);
      session.getSerializedKeyPackage();
      const { commit } = session.processProposals(ProposalsOperationType.APPEND, APPENDING_PROPOSALS);
      session.processCommit(commit!);
      break;
  }

  return session;
};

/** Only run this test on release builds, since tls-codec will panic on bad data in debug builds. */
const testOnRelease: TestFn | SkipFn = DEBUG_BUILD ? test.skip : test;

// new DAVESession()
{
  test('new DAVESession() creates session successfully', (t) => {
    const session = createSession();

    t.true(session instanceof DAVESession, 'Expected session to be instance of DAVESession');
    t.is(session.protocolVersion, 1);
    t.is(session.userId, MY_USER_ID);
    t.is(session.channelId, CHANNEL_ID);
    t.is(session.status, SessionStatus.INACTIVE);
  });

  test('new DAVESession() throws on invalid protocol version', (t) => {
    t.throws(() => new DAVESession(0, MY_USER_ID, CHANNEL_ID));
  });
}

// setExternalSender()
{
  test('setExternalSender() runs successfully on valid data', (t) => {
    const session = createSession();

    t.notThrows(() => session.setExternalSender(EXTERNAL_SENDER));
    t.is(session.status, SessionStatus.PENDING);
  });

  testOnRelease('setExternalSender() throws on invalid data', (t) => {
    const invalidExternalSender = Buffer.from([0x40, 0x41]);

    const session = createSession();

    t.throws(() => session.setExternalSender(invalidExternalSender));
    t.throws(() => session.setExternalSender(EMPTY_BUFFER));
  });
}

// getSerializedKeyPackage()
{
  test('getSerializedKeyPackage() returns a key package', (t) => {
    const session = createSession();

    const keypackage = session.getSerializedKeyPackage();
    t.true(keypackage instanceof Buffer);
    t.true(keypackage.byteLength > 300, `Expected a bigger key package (got ${keypackage.byteLength})`); // KeyPackages are usually ~390 bytes
  });

  test('getSerializedKeyPackage() returns different key packages', (t) => {
    const session = createSession();

    const keypackage1 = session.getSerializedKeyPackage();
    const keypackage2 = session.getSerializedKeyPackage();
    t.notDeepEqual(keypackage1, keypackage2, 'Expected key packages to be different');
  });
}

// processProposals()
{
  test('processProposals() returns commit & welcome on appending proposals', (t) => {
    const session = createSession(SessionStatus.PENDING);

    const result = session.processProposals(ProposalsOperationType.APPEND, APPENDING_PROPOSALS);
    t.deepEqual(Object.keys(result), ['commit', 'welcome']);
    t.true(Buffer.isBuffer(result.commit), 'Expected result.commit to be a Buffer');
    t.true(Buffer.isBuffer(result.welcome), 'Expected result.welcome to be a Buffer');
    t.is(session.status, SessionStatus.AWAITING_RESPONSE);
  });

  test('processProposals() returns nothing when theres no queued proposals', (t) => {
    const session = createSession(SessionStatus.PENDING);

    session.processProposals(ProposalsOperationType.APPEND, APPENDING_PROPOSALS);
    const result = session.processProposals(ProposalsOperationType.REVOKE, REVOKING_PROPOSALS);
    t.deepEqual(Object.keys(result), []);
    t.not(session.status, SessionStatus.AWAITING_RESPONSE);
  });

  test('processProposals() does not throw on recognized users', (t) => {
    t.notThrows(() =>
      createSession(SessionStatus.PENDING).processProposals(ProposalsOperationType.APPEND, APPENDING_PROPOSALS, [
        OTHER_USER_ID,
      ]),
    );
  });

  test('processProposals() throws on invalid proposal op type', (t) => {
    const session = createSession(SessionStatus.PENDING);

    // @ts-expect-error
    t.throws(() => session.processProposals(2, EMPTY_BUFFER));
  });

  test('processProposals() throws on inactive sessions', (t) => {
    t.throws(() =>
      createSession(SessionStatus.INACTIVE).processProposals(ProposalsOperationType.APPEND, APPENDING_PROPOSALS),
    );
  });

  testOnRelease('processProposals() throws on invalid proposals', (t) => {
    const session = createSession(SessionStatus.PENDING);

    t.throws(() => session.processProposals(ProposalsOperationType.APPEND, EMPTY_BUFFER));
  });

  test('processProposals() throws on unrecognized users', (t) => {
    t.throws(() =>
      createSession(SessionStatus.PENDING).processProposals(ProposalsOperationType.APPEND, APPENDING_PROPOSALS, []),
    );
  });
}

// processCommit()
{
  test('processCommit() runs successfully (can process our own commit)', (t) => {
    const session = createSession(SessionStatus.PENDING);

    const { commit } = session.processProposals(ProposalsOperationType.APPEND, APPENDING_PROPOSALS);
    t.notThrows(() => session.processCommit(commit!));
    t.is(session.status, SessionStatus.ACTIVE);
    t.true(session.ready);
  });

  test('processCommit() throws on non-awaiting session', (t) => {
    // Should probably have *valid* commits here
    t.throws(() => createSession(SessionStatus.INACTIVE).processCommit(EMPTY_BUFFER));
    t.throws(() => createSession(SessionStatus.PENDING).processCommit(EMPTY_BUFFER));
  });

  testOnRelease('processCommit() throws on invalid commit', (t) => {
    const session = createSession(SessionStatus.AWAITING_RESPONSE);

    t.throws(() => session.processCommit(EMPTY_BUFFER));
  });
}

// voicePrivacyCode
{
  test('session.voicePrivacyCode is empty on non-established groups', (t) => {
    t.is(createSession(SessionStatus.INACTIVE).voicePrivacyCode, '');
    t.is(createSession(SessionStatus.PENDING).voicePrivacyCode, '');
    t.is(createSession(SessionStatus.AWAITING_RESPONSE).voicePrivacyCode, '');
  });

  test('session.voicePrivacyCode is not empty on established groups', (t) => {
    t.not(createSession(SessionStatus.ACTIVE).voicePrivacyCode, '');
  });
}

// epoch
{
  test('session.epoch is null when theres no group', (t) => {
    t.is(createSession(SessionStatus.INACTIVE).epoch, null);
  });

  test('session.epoch is 0 when theres a pending group', (t) => {
    t.is(createSession(SessionStatus.PENDING).epoch, 0n);
    t.is(createSession(SessionStatus.AWAITING_RESPONSE).epoch, 0n);
  });

  test('session.epoch is updated when theres an active group', (t) => {
    t.is(createSession(SessionStatus.ACTIVE).epoch, 1n);
  });
}

// ownLeafIndex
{
  test('session.ownLeafIndex is null when theres no group', (t) => {
    t.is(createSession(SessionStatus.INACTIVE).ownLeafIndex, null);
  });

  test('session.ownLeafIndex is not null when theres a group', (t) => {
    t.is(createSession(SessionStatus.PENDING).ownLeafIndex, 0);
    t.is(createSession(SessionStatus.AWAITING_RESPONSE).ownLeafIndex, 0);
    t.is(createSession(SessionStatus.ACTIVE).ownLeafIndex, 0);
  });
}

// getUserIds()
{
  test('getUserIds() returns empty array on non-established groups', (t) => {
    t.deepEqual(createSession(SessionStatus.INACTIVE).getUserIds(), []);
  });

  test('getUserIds() returns your own ID on pending groups', (t) => {
    t.deepEqual(createSession(SessionStatus.PENDING).getUserIds(), [MY_USER_ID]);
    t.deepEqual(createSession(SessionStatus.AWAITING_RESPONSE).getUserIds(), [MY_USER_ID]);
  });

  test('getUserIds() returns populated array of members', (t) => {
    t.deepEqual(createSession(SessionStatus.ACTIVE).getUserIds(), [MY_USER_ID, OTHER_USER_ID]);
  });
}

// encrypt()/decrypt()
{
  test('encrypt() returns silence frame when given one', (t) => {
    const session = createSession(SessionStatus.ACTIVE);
    t.deepEqual(session.encryptOpus(SILENCE_FRAME), SILENCE_FRAME);
  });

  test('decrypt() returns silence frame when given one', (t) => {
    const session = createSession(SessionStatus.ACTIVE);
    t.deepEqual(session.decrypt(OTHER_USER_ID, MediaType.AUDIO, SILENCE_FRAME), SILENCE_FRAME);
  });
}

// getEncryptionStats()/getDecryptionStats()
{
  test('getEncryptionStats() returns stats', (t) => {
    const session = createSession(SessionStatus.ACTIVE);
    t.deepEqual(session.getEncryptionStats(), { successes: 0, failures: 0, duration: 0, attempts: 0, maxAttempts: 0 });
  });

  test('getDecryptionStats() returns stats', (t) => {
    const session = createSession(SessionStatus.ACTIVE);
    t.deepEqual(session.getDecryptionStats(OTHER_USER_ID), { successes: 0, failures: 0, duration: 0, passthroughs: 0, attempts: 0 });
  });
}

// TODO add passthrough tests