# Toy project: finds the CA certificate bundle used for TLS.
import os

import certifi


def bundle_path():
    return certifi.where()


def test_bundle_file_exists():
    assert os.path.isfile(bundle_path())


def test_bundle_contains_certificates():
    with open(bundle_path()) as handle:
        assert "BEGIN CERTIFICATE" in handle.read()
