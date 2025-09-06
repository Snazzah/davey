import pytest
import davey


def to_int_list_str(b):
    return "".join(map(str, list(b)))


def test_generate_key_fingerprint_returns_valid_fingerprints():
    short_data = bytes(33)
    assert (
        to_int_list_str(davey.generate_key_fingerprint(0, short_data, 1234))
        == "000000000000000000000000000000000000000004210"
    )

    long_data = bytes(65)
    assert (
        to_int_list_str(davey.generate_key_fingerprint(0, long_data, 12345678))
        == "0000000000000000000000000000000000000000000000000000000000000000000000001889778"
    )


def test_generate_key_fingerprint_throws_on_invalid_arguments():
    data = bytes(33)
    # Invalid fingerprint version
    with pytest.raises(Exception):
        davey.generate_key_fingerprint(1, data, 1234)
    # Zero-length key
    with pytest.raises(Exception):
        davey.generate_key_fingerprint(0, bytes(), 1234)


def test_generate_pairwise_fingerprint_returns_valid_fingerprints():
    data1 = bytes(33)
    data2 = bytes(65)
    expected = bytes(
        [
            133,
            129,
            241,
            44,
            36,
            135,
            79,
            195,
            27,
            28,
            151,
            69,
            124,
            197,
            189,
            41,
            192,
            7,
            16,
            45,
            79,
            247,
            138,
            58,
            126,
            161,
            178,
            136,
            12,
            109,
            96,
            164,
            169,
            92,
            2,
            232,
            136,
            174,
            74,
            156,
            173,
            144,
            191,
            184,
            34,
            45,
            242,
            136,
            41,
            133,
            14,
            158,
            119,
            79,
            204,
            48,
            6,
            220,
            121,
            6,
            242,
            11,
            164,
            60,
        ]
    )
    result = davey.generate_pairwise_fingerprint(0, data1, 1234, data2, 5678)
    assert bytes(result) == expected


def test_generate_pairwise_fingerprint_resolves_bad_sorts():
    data1 = bytes([0, 100])
    data2 = bytes([0, 20])
    expected = bytes(
        [
            141,
            169,
            194,
            143,
            22,
            72,
            22,
            245,
            13,
            140,
            66,
            228,
            159,
            195,
            101,
            106,
            119,
            240,
            69,
            191,
            178,
            227,
            194,
            126,
            162,
            255,
            222,
            148,
            138,
            5,
            33,
            215,
            240,
            167,
            234,
            245,
            149,
            182,
            46,
            20,
            4,
            83,
            191,
            31,
            165,
            74,
            253,
            165,
            199,
            16,
            29,
            71,
            193,
            205,
            169,
            154,
            255,
            154,
            34,
            30,
            94,
            171,
            247,
            43,
        ]
    )
    result = davey.generate_pairwise_fingerprint(0, data1, 1, data2, 2)
    assert bytes(result) == expected


def test_generate_pairwise_fingerprint_throws_on_invalid_arguments():
    data = bytes(33)
    # Invalid fingerprint version
    with pytest.raises(Exception):
        davey.generate_pairwise_fingerprint(1, data, 1234, data, 5678)
    # Zero-length key
    with pytest.raises(Exception):
        davey.generate_pairwise_fingerprint(0, bytes(), 1234, data, 5678)
