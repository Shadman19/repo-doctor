# Toy project: converts international domain names to ASCII and back.
import idna


def to_ascii(domain):
    return idna.encode(domain).decode("ascii")


def test_encode_unicode_domain():
    assert to_ascii("münchen.de") == "xn--mnchen-3ya.de"


def test_round_trip():
    assert idna.decode(to_ascii("bücher.example")) == "bücher.example"
