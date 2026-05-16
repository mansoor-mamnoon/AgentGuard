from importlib.metadata import version


def test_version_exists():
    v = version("llmfirewall")
    assert isinstance(v, str)
    assert v.count(".") == 2
