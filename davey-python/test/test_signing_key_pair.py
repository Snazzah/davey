import davey


def test_generate_p256_keypair_returns_valid_keys():
    result = davey.generate_p256_keypair()

    assert isinstance(result.private, bytes)
    assert isinstance(result.public, bytes)
