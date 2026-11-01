# Toy project: splits URLs into parts with urllib3.
from urllib3.util import parse_url


def host_and_port(url):
    parsed = parse_url(url)
    return parsed.host, parsed.port


def test_host_and_port():
    assert host_and_port("http://example.com:8080/path") == ("example.com", 8080)


def test_missing_port_is_none():
    assert host_and_port("https://example.com/") == ("example.com", None)
