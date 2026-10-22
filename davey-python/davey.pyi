"""
Davey

A Discord Audio & Video End-to-End Encryption (DAVE) Protocol implementation in Python.

:copyright: (c) 2025-present Snazzah
:license: MIT

"""

from typing import Final, List, Optional
from enum import Enum

__version__: str = ...
__author__: Final = "Snazzah"
__copyright__: Final = "Copyright 2025-present Snazzah"
__license__: Final = "MIT"
DEBUG_BUILD: bool = ...
""" Whether davey is using a debug build."""
DAVE_PROTOCOL_VERSION: int = ...
"""The maximum supported version of the DAVE protocol."""

class SigningKeyPair:
    """
    A signing key pair. This is needed if you want to pass your own key pair or store the key pair for later.

    :param private: The private key.
    :param public: The public key.
    """
    def __init__(self, private: bytes, public: bytes) -> None: ...
    private: bytes
    """The private key of this key pair."""
    public: bytes
    """The public key of this key pair."""
    def __repr__(self) -> str: ...

def generate_p256_keypair() -> SigningKeyPair:
    """Create a P256 signing key pair."""
    ...

def generate_displayable_code(data: bytes, desired_length: int, group_size: int) -> str:
    """
    Generate a displayable code.

    See: https://daveprotocol.com/#displayable-codes

    :param data: The data to generate a code with.
    :param desired_length: The desired length of the code.
    :param group_size: The group size of the code.
    """
    ...

def generate_key_fingerprint(version: int, key: bytes, user_id: int) -> bytes:
    """
    Generate a key fingerprint.

    See: https://daveprotocol.com/#verification-fingerprint

    :param version: The version of the fingerprint.
    :param key: The key to fingerprint.
    :param user_id: The user ID of this fingerprint.
    """
    ...

def generate_pairwise_fingerprint(
    version: int,
    local_key: bytes,
    local_user_id: int,
    remote_key: bytes,
    remote_user_id: int,
) -> bytes:
    """
    Generate a pairwise fingerprint.

    See: https://daveprotocol.com/#verification-fingerprint

    :param version: The version of the fingerprint.
    :param local_key: The local user's key.
    :param local_user_id: The local user's ID.
    :param remote_key: The remote user's key.
    :param remote_user_id: The remote user's ID.
    """
    ...

class Codec(Enum):
    """The type of codec being used."""

    unknown = 0
    opus = 1
    vp8 = 2
    vp9 = 3
    h264 = 4
    h265 = 5
    av1 = 6

class MediaType(Enum):
    """The type of media being referenced."""

    audio = 0
    video = 1

class ProposalsOperationType(Enum):
    """
    The operation type of the proposals payload.
    See the [DAVE Protocol Whitepaper on opcode 27](https://daveprotocol.com/#dave_mls_proposals-27) for technical details.
    """

    append = 0
    revoke = 1

class SessionStatus(Enum):
    """The status of the DAVE session."""

    inactive = 0
    pending = 1
    awaiting_response = 2
    active = 3

class EncryptionStats:
    successes: int
    """Number of encryption successes"""
    failures: int
    """Number of encryption failures"""
    duration: int
    """Total encryption duration in microseconds"""
    attempts: int
    """Total amounts of encryption attempts"""
    max_attempts: int
    """Maximum attempts reached at encryption"""

class DecryptionStats:
    successes: int
    """Number of decryption successes"""
    failures: int
    """Number of decryption failures"""
    duration: int
    """Total decryption duration in microseconds"""
    attempts: int
    """Total amounts of decryption attempts"""
    passthroughs: int
    """Total amounts of packets that passed through"""

class CommitWelcome:
    """
    Contains the commit and optional welcome for
    [dave_mls_commit_welcome (28)](https://daveprotocol.com/#dave_mls_commit_welcome-28).
    """

    commit: bytes
    welcome: Optional[bytes]

class DaveSession:
    """
    A DAVE session.

    :param protocol_version: The protocol version to use.
    :param user_id: The user ID of the session.
    :param channel_id: The channel ID of the session.
    :param key_pair: The key pair to use for this session. Will generate a new one if not specified.
    """
    def __init__(
        self,
        protocol_version: int,
        user_id: int,
        channel_id: int,
        key_pair: Optional[SigningKeyPair] = None,
    ) -> None: ...

    protocol_version: int
    """he DAVE protocol version used for this session."""
    user_id: int
    """The user ID for this session."""
    channel_id: int
    """The channel ID (group ID in MLS standards) for this session."""
    epoch: Optional[int]
    """The epoch for this session, `undefined` if there is no group yet."""
    own_leaf_index: Optional[int]
    """Your own leaf index for this session, `undefined` if there is no group yet."""
    ciphersuite: int
    """The ciphersuite being used in this session."""
    status: SessionStatus
    """The current status of the session."""
    ready: bool
    """Whether the session is ready to encrypt/decrypt."""
    voice_privacy_code: Optional[str]
    """
    Get the voice privacy code of this session's group.
    The result of this is created and cached each time a new transition is executed.

    See: https://daveprotocol.com/#displayable-codes
    """

    def reset(self) -> None:
        """
        Resets the session by deleting the group and clearing the storage.
        """
        ...
    def reinit(
        self,
        protocol_version: int,
        user_id: int,
        channel_id: int,
        key_pair: Optional[SigningKeyPair] = None,
    ) -> None:
        """
        Resets and re-initializes the session.

        :param protocol_version: The protocol version to use.
        :param user_id: The user ID of the session.
        :param channel_id: The channel ID of the session.
        :param key_pair: The key pair to use for this session. Will generate a new one if not specified.
        """
        ...
    def get_epoch_authenticator(self) -> Optional[bytes]:
        """Get the epoch authenticator of this session's group."""
        ...
    def set_external_sender(self, external_sender_data: bytes) -> None:
        """
        Set the external sender this session will recieve from.
        See the [DAVE Protocol Whitepaper on opcode 25](https://daveprotocol.com/#dave_mls_external_sender_package-25) for technical details.

        :param external_sender_data: The serialized external sender data.
        """
        ...
    def get_serialized_key_package(self) -> bytes:
        """
        Create, store, and return the serialized key package buffer.
        Key packages are not meant to be reused, and will be recreated on each call of this function.
        """
        ...
    def process_proposals(
        self,
        operation_type: ProposalsOperationType,
        proposals: bytes,
        expected_user_ids: Optional[List[int]] = None,
    ) -> Optional[CommitWelcome]:
        """
        Process proposals from the voice server.
        See the [DAVE Protocol Whitepaper on opcode 27](https://daveprotocol.com/#dave_mls_proposals-27) for technical details.

        :param operation_type: The operation type of the proposals.
        :param proposals: The operation type of the proposals.
        :param expected_user_ids: The expected user IDs to come from the proposals.
            If provided, this will reject unexpected user IDs.
        """
        ...
    def process_welcome(
        self,
        welcome: bytes,
        recognized_user_ids: Optional[List[int]] = None,
    ) -> None:
        """
        Process a welcome message.
        See the [DAVE Protocol Whitepaper on opcode 30](https://daveprotocol.com/#dave_mls_welcome-30) for technical details.

        :param welcome: The welcome message to process.
        :param recognized_user_ids: The recognized user IDs expected to be in the welcomed group.
        """
        ...
    def process_commit(self, commit: bytes) -> None:
        """
        Process a commit.
        See the [DAVE Protocol Whitepaper on opcode 29](https://daveprotocol.com/#dave_mls_announce_commit_transition-29) for technical details.

        :param commit: The commit to process.
        """
        ...
    def get_verification_code(self, user_id: int) -> str:
        """
        Get the verification code of another member of the group.

        See: https://daveprotocol.com/#displayable-codes

        :param user_id: The ID of the user to get the verification code of.
        """
        ...
    def get_pairwise_fingerprint(self, version: int, user_id: int) -> bytes:
        """
        Create a pairwise fingerprint of you and another member.

        See: https://daveprotocol.com/#verification-fingerprint

        :param version: The version of the fingerprint.
        :param user_id: The ID of the user to get the pairwise fingerprint of.
        """
        ...
    def encrypt(self, media_type: MediaType, codec: Codec, packet: bytes) -> bytes:
        """
        End-to-end encrypt a packet.

        :param media_type: The type of media to encrypt.
        :param codec: The codec of the packet.
        :param packet: The packet to encrypt.
        """
        ...
    def encrypt_opus(self, packet: bytes) -> bytes:
        """
        End-to-end encrypt an opus packet.

        :param packet: The packet to encrypt.
        """
        ...
    def get_encryption_stats(
        self, media_type: Optional[MediaType] = None
    ) -> EncryptionStats:
        """
        Get encryption stats.

        :param media_type: The media type to get stats for. Defaults to audio.
        """
        ...
    def decrypt(self, user_id: int, media_type: MediaType, packet: bytes) -> bytes:
        """
        Decrypt an end-to-end encrypted packet.

        :param user_id: The ID of the user to decrypt the packet for.
        :param media_type: The type of media to decrypt.
        :param packet: The packet to decrypt.
        """
        ...
    def get_decryption_stats(
        self, user_id: int, media_type: Optional[MediaType] = None
    ) -> Optional[DecryptionStats]:
        """
        Get decryption stats.

        :param user_id: The ID of the user to get stats for.
        :param media_type: The media type to get stats for. Defaults to audio.
        """
        ...
    def get_user_ids(self) -> List[str]:
        """Get the IDs of the users in the current group."""
        ...
    def can_passthrough(self, user_id: int) -> bool:
        """
        Check whether this user's decryptor is in passthrough mode.
        If passthrough mode is enabled, then unencrypted packets are allowed to be passed through the decryptor.

        :param user_id: The ID of the user to check their decryptoe's passthrough mode.
        """
        ...
    def set_passthrough_mode(
        self, passthrough_mode: bool, transition_expiry: Optional[int] = None
    ) -> None:
        """
        Set whether passthrough mode is enabled on all decryptors.

        :param passthrough_mode: Whether to enable passthrough mode.
        :param transition_expiry: The transition expiry (in seconds) to use when disabling passthrough mode, defaults to 10 seconds.
        """
        ...
    def __repr__(self) -> str: ...
