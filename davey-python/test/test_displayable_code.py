import os
import pytest
import davey


# generate_displayable_code tests
def test_generate_displayable_code_returns_valid_codes():
    short_data = bytes([0xAA, 0xBB, 0xCC, 0xDD, 0xEE])
    assert davey.generate_displayable_code(short_data, 5, 5) == "05870"

    long_data = bytes.fromhex(
        "aabbccddeebbccddeeffccddeeffaaddeeffaabbeeffaabbccffaabbccdd"
    )
    assert (
        davey.generate_displayable_code(long_data, 30, 5)
        == "058708105556138052119572494877"
    )


def test_generate_displayable_code_throws_on_invalid_arguments():
    too_short_data = bytes([0xAA, 0xBB, 0xCC, 0xDD])
    with pytest.raises(Exception):
        davey.generate_displayable_code(too_short_data, 5, 5)

    good_data = bytes([0xAA, 0xBB, 0xCC, 0xDD])
    with pytest.raises(Exception):
        davey.generate_displayable_code(good_data, 4, 3)

    random_data = os.urandom(1024)
    with pytest.raises(Exception):
        davey.generate_displayable_code(random_data, 1024, 11)
