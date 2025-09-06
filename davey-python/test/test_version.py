import davey


def test_version_and_constants():
    assert isinstance(davey.__version__, str)
    assert isinstance(davey.__author__, str)
    assert isinstance(davey.__copyright__, str)
    assert isinstance(davey.__license__, str)
    assert isinstance(davey.DEBUG_BUILD, bool)
    assert isinstance(davey.DAVE_PROTOCOL_VERSION, int)
