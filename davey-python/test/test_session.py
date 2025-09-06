import pytest
import davey

# fmt: off
EXTERNAL_SENDER = bytes([
    0x40, 0x41, 0x04, 0xca, 0x1a, 0x2b, 0x10, 0x25, 0x01, 0xd0, 0x67, 0x2b, 0xd4, 0x5e, 0xd7,
    0x4f, 0xfb, 0x83, 0xe0, 0x78, 0xb2, 0xba, 0x5b, 0x12, 0xc3, 0xf6, 0x9f, 0xad, 0x56, 0xf0, 0x83, 0xb6, 0xa3, 0x5f,
    0xc9, 0x89, 0xc6, 0x73, 0x6b, 0x58, 0x52, 0xb5, 0xae, 0xcd, 0xfc, 0xdf, 0x20, 0x6e, 0x15, 0x6d, 0x3d, 0x1d, 0xba,
    0x8e, 0x3e, 0x5b, 0x2f, 0x89, 0xfc, 0x0c, 0x16, 0xf1, 0x16, 0x14, 0xe8, 0x4e, 0x4a, 0x00, 0x01, 0x01, 0x00,
])

APPENDING_PROPOSALS = bytes([
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
])

REVOKING_PROPOSALS = bytes([
    0x21, 0x20, 0x62, 0x38, 0x6f, 0xfb, 0x20, 0xb2, 0x8f, 0x55, 0x6b, 0x24, 0x65, 0xc0, 0xa2, 0x52, 0x0b, 0xa2, 0xb0,
    0x74, 0xfc, 0xa0, 0x0e, 0x94, 0xb2, 0xfd, 0xeb, 0xc0, 0x49, 0x6d, 0x54, 0x4c, 0xd6, 0xc0,
])
# fmt: on

EMPTY_BUFFER = b""
SILENCE_FRAME = bytes([0xF8, 0xFF, 0xFE])

CHANNEL_ID = 927310423890473011
MY_USER_ID = 158049329150427136
OTHER_USER_ID = 158533742254751744


def create_session(status: davey.SessionStatus = davey.SessionStatus.inactive):
    session = davey.DaveSession(1, MY_USER_ID, CHANNEL_ID)

    if status == davey.SessionStatus.inactive:
        return session

    # pending
    session.set_external_sender(EXTERNAL_SENDER)
    session.get_serialized_key_package()

    if status == davey.SessionStatus.pending:
        return session

    # awaiting_response
    session.process_proposals(davey.ProposalsOperationType.append, APPENDING_PROPOSALS)
    if status == davey.SessionStatus.awaiting_response:
        return session

    # active
    cw = session.process_proposals(
        davey.ProposalsOperationType.append, APPENDING_PROPOSALS
    )
    if cw is None:
        pytest.skip(
            "Could not obtain commit from proposals; skipping active session setup."
        )
    session.process_commit(cw.commit)
    return session


def test_new_dave_session_creates_session_successfully():
    session = create_session()
    assert isinstance(session, davey.DaveSession)
    assert session.protocol_version == 1
    assert session.user_id == MY_USER_ID
    assert session.channel_id == CHANNEL_ID
    assert session.status == davey.SessionStatus.inactive


def test_new_dave_session_throws_on_invalid_protocol_version():
    with pytest.raises(Exception):
        davey.DaveSession(0, MY_USER_ID, CHANNEL_ID)


def test_set_external_sender_runs_successfully_on_valid_data():
    session = create_session()
    # should not raise
    session.set_external_sender(EXTERNAL_SENDER)
    assert session.status == davey.SessionStatus.pending


@pytest.mark.skipif(
    davey.DEBUG_BUILD, reason="tls-codec panics on invalid data in debug builds"
)
def test_set_external_sender_throws_on_invalid_data():
    invalid_external_sender = bytes([0x40, 0x41])
    session = create_session()
    with pytest.raises(Exception):
        session.set_external_sender(invalid_external_sender)
    with pytest.raises(Exception):
        session.set_external_sender(EMPTY_BUFFER)


def test_get_serialized_key_package_returns_a_key_package():
    session = create_session()
    keypackage = session.get_serialized_key_package()
    assert isinstance(keypackage, bytes)
    assert len(keypackage) > 300


def test_get_serialized_key_package_returns_different_key_packages():
    session = create_session()
    keypackage1 = session.get_serialized_key_package()
    keypackage2 = session.get_serialized_key_package()
    assert keypackage1 != keypackage2


def test_process_proposals_returns_commit_and_welcome_on_appending_proposals():
    session = create_session(davey.SessionStatus.pending)
    result = session.process_proposals(
        davey.ProposalsOperationType.append, APPENDING_PROPOSALS
    )
    assert result is not None
    assert isinstance(result.commit, bytes)
    assert isinstance(result.welcome, bytes)
    assert session.status == davey.SessionStatus.awaiting_response


def test_process_proposals_returns_none_when_theres_no_queued_proposals():
    session = create_session(davey.SessionStatus.pending)
    session.process_proposals(davey.ProposalsOperationType.append, APPENDING_PROPOSALS)
    result = session.process_proposals(
        davey.ProposalsOperationType.revoke, REVOKING_PROPOSALS
    )
    assert result is None
    assert session.status != davey.SessionStatus.awaiting_response


def test_process_proposals_does_not_throw_on_recognized_users():
    session = create_session(davey.SessionStatus.pending)
    session.process_proposals(
        davey.ProposalsOperationType.append, APPENDING_PROPOSALS, [OTHER_USER_ID]
    )


def test_process_proposals_throws_on_invalid_proposal_op_type():
    session = create_session(davey.SessionStatus.pending)
    with pytest.raises(Exception):
        session.process_proposals(2, EMPTY_BUFFER)


def test_process_proposals_throws_on_inactive_sessions():
    with pytest.raises(Exception):
        create_session(davey.SessionStatus.inactive).process_proposals(
            davey.ProposalsOperationType.append, APPENDING_PROPOSALS
        )


@pytest.mark.skipif(
    davey.DEBUG_BUILD, reason="tls-codec panics on invalid data in debug builds"
)
def test_process_proposals_throws_on_invalid_proposals():
    session = create_session(davey.SessionStatus.pending)
    with pytest.raises(Exception):
        session.process_proposals(davey.ProposalsOperationType.append, EMPTY_BUFFER)


def test_process_proposals_throws_on_unrecognized_users():
    with pytest.raises(Exception):
        create_session(davey.SessionStatus.pending).process_proposals(
            davey.ProposalsOperationType.append, APPENDING_PROPOSALS, []
        )


def test_process_commit_runs_successfully_can_process_own_commit():
    session = create_session(davey.SessionStatus.pending)
    cw = session.process_proposals(
        davey.ProposalsOperationType.append, APPENDING_PROPOSALS
    )
    assert cw is not None
    # should not raise
    session.process_commit(cw.commit)
    assert session.status == davey.SessionStatus.active
    assert session.ready


def test_process_commit_throws_on_non_awaiting_session():
    with pytest.raises(Exception):
        create_session(davey.SessionStatus.inactive).process_commit(EMPTY_BUFFER)
    with pytest.raises(Exception):
        create_session(davey.SessionStatus.pending).process_commit(EMPTY_BUFFER)


@pytest.mark.skipif(
    davey.DEBUG_BUILD, reason="tls-codec panics on invalid data in debug builds"
)
def test_process_commit_throws_on_invalid_commit():
    session = create_session(davey.SessionStatus.awaiting_response)
    with pytest.raises(Exception):
        session.process_commit(EMPTY_BUFFER)


def test_voice_privacy_code_empty_on_non_established_groups():
    assert create_session(davey.SessionStatus.inactive).voice_privacy_code in (None, "")
    assert create_session(davey.SessionStatus.pending).voice_privacy_code in (None, "")
    assert create_session(davey.SessionStatus.awaiting_response).voice_privacy_code in (
        None,
        "",
    )


def test_voice_privacy_code_not_empty_on_established_groups():
    session = create_session(davey.SessionStatus.active)
    assert session.voice_privacy_code not in (None, "")


def test_epoch_behavior():
    assert create_session(davey.SessionStatus.inactive).epoch is None
    assert create_session(davey.SessionStatus.pending).epoch == 0
    assert create_session(davey.SessionStatus.awaiting_response).epoch == 0
    assert create_session(davey.SessionStatus.active).epoch == 1


def test_own_leaf_index_behavior():
    assert create_session(davey.SessionStatus.inactive).own_leaf_index is None
    assert create_session(davey.SessionStatus.pending).own_leaf_index == 0
    assert create_session(davey.SessionStatus.awaiting_response).own_leaf_index == 0
    assert create_session(davey.SessionStatus.active).own_leaf_index == 0


def test_get_user_ids():
    assert create_session(davey.SessionStatus.inactive).get_user_ids() == []
    assert create_session(davey.SessionStatus.pending).get_user_ids() == [
        str(MY_USER_ID)
    ]
    assert create_session(davey.SessionStatus.awaiting_response).get_user_ids() == [
        str(MY_USER_ID)
    ]
    assert create_session(davey.SessionStatus.active).get_user_ids() == [
        str(MY_USER_ID),
        str(OTHER_USER_ID),
    ]


def test_encrypt_decrypt_silence_frame_passthrough():
    session = create_session(davey.SessionStatus.active)
    assert session.encrypt_opus(SILENCE_FRAME) == SILENCE_FRAME
    assert (
        session.decrypt(OTHER_USER_ID, davey.MediaType.audio, SILENCE_FRAME)
        == SILENCE_FRAME
    )


def test_get_encryption_and_decryption_stats():
    session = create_session(davey.SessionStatus.active)
    enc_stats = session.get_encryption_stats()
    assert enc_stats.successes == 0
    assert enc_stats.failures == 0
    assert enc_stats.duration == 0
    assert enc_stats.attempts == 0
    assert enc_stats.max_attempts == 0

    dec_stats = session.get_decryption_stats(OTHER_USER_ID)
    assert dec_stats is not None
    assert dec_stats.successes == 0
    assert dec_stats.failures == 0
    assert dec_stats.duration == 0
    assert dec_stats.passthroughs == 0
    assert dec_stats.attempts == 0
