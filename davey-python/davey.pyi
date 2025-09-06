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
DAVE_PROTOCOL_VERSION: int = ...

class SigningKeyPair:
    """
    A signing key pair. This is needed if you want to pass your own key pair or store the key pair for later.

    :param private: The private key.
    :param public: The public key.
    """
    def __init__(self, private: bytes, public: bytes) -> None: ...
    private: bytes
    public: bytes
    def __repr__(self) -> str: ...

def generate_p256_keypair() -> SigningKeyPair:
    """Create a P256 signing key pair."""
    ...

def generate_displayable_code(data: bytes, desired_length: int, group_size: int) -> str:
    """
    Generate a displayable code.

    See: https://daveprotocol.com/#displayable-codes
    """
    ...

def generate_key_fingerprint(version: int, key: bytes, group_size: int) -> bytes:
    """
    Generate a key fingerprint.

    See: https://daveprotocol.com/#verification-fingerprint
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
    """
    ...

class Codec(Enum):
    unknown = 0
    opus = 1
    vp8 = 2
    vp9 = 3
    h264 = 4
    h265 = 5
    av1 = 6

class MediaType(Enum):
    audio = 0
    video = 1

class ProposalsOperationType(Enum):
    append = 0
    remoke = 1

class SessionStatus(Enum):
    inactive = 0
    pending = 1
    awaiting_response = 2
    active = 3

class EncryptionStats:
    successes: int
    failures: int
    duration: int
    attempts: int
    max_attempts: int

class DecryptionStats:
    successes: int
    failures: int
    duration: int
    attempts: int
    passthroughs: int

class CommitWelcome:
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
    user_id: int
    channel_id: int
    epoch: Optional[int]
    own_leaf_index: Optional[int]
    ciphersuite: int
    status: SessionStatus
    ready: bool
    voice_privacy_code: Optional[str]

    def reset(self) -> None: ...
    def reinit(
        self,
        protocol_version: int,
        user_id: int,
        channel_id: int,
        key_pair: Optional[SigningKeyPair] = None,
    ) -> None: ...
    def get_epoch_authenticator(self) -> Optional[bytes]: ...
    def set_external_sender(self, external_sender_data: bytes) -> None: ...
    def get_serialized_key_package(self) -> bytes: ...
    def process_proposals(
        self,
        operation_type: ProposalsOperationType,
        proposals: bytes,
        expected_user_ids: Optional[List[int]] = None,
    ) -> Optional[CommitWelcome]: ...
    def process_welcome(self, welcome: bytes) -> None: ...
    def get_verification_code(self, user_id: int) -> str: ...
    def get_pairwise_fingerprint(self, version: int, user_id: int) -> bytes: ...
    def encrypt(self, media_type: MediaType, codec: Codec, packet: bytes) -> bytes: ...
    def encrypt_opus(self, packet: bytes) -> bytes: ...
    def get_encryption_stats(
        self, media_type: Optional[MediaType] = None
    ) -> EncryptionStats: ...
    def decrypt(self, user_id: int, media_type: MediaType, packet: bytes) -> bytes: ...
    def get_decryption_stats(
        self, user_id: int, media_type: Optional[MediaType] = None
    ) -> Optional[DecryptionStats]: ...
    def process_commit(self, commit: bytes) -> None: ...
    def get_user_ids(self) -> List[str]: ...
    def can_passthrough(self, user_id: int) -> bool: ...
    def set_passthrough_mode(
        self, passthrough_mode: bool, transition_expiry: Optional[int] = None
    ) -> None: ...
    def __repr__(self) -> str: ...
