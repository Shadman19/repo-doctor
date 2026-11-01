# Toy project: safe file names and password hashing with Werkzeug.
from werkzeug.security import check_password_hash, generate_password_hash
from werkzeug.utils import secure_filename


def test_secure_filename_strips_path():
    assert secure_filename("../../etc/passwd") == "etc_passwd"


def test_password_hash_round_trip():
    hashed = generate_password_hash("s3cret")
    assert check_password_hash(hashed, "s3cret")
    assert not check_password_hash(hashed, "wrong")
