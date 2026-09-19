import bcrypt

from app.security.hashing import hash_password, verify_password


def test_new_passwords_are_hashed_with_argon2id():
    hashed = hash_password("Str0ng!Passw0rd")
    assert hashed.startswith("$argon2id$")
    assert hashed != "Str0ng!Passw0rd"


def test_argon2id_hash_verifies_correctly():
    hashed = hash_password("Str0ng!Passw0rd")
    assert verify_password("Str0ng!Passw0rd", hashed) is True
    assert verify_password("WrongPassword", hashed) is False


def test_legacy_bcrypt_hash_still_verifies():
    """Simulates an account created before the Argon2id migration: its
    password_hash is a bcrypt hash. verify_password must still accept the
    correct password against it, so existing users are never locked out."""
    legacy_hash = bcrypt.hashpw(b"OldAccountPassword1!", bcrypt.gensalt(rounds=4)).decode("utf-8")
    assert legacy_hash.startswith("$2b$")
    assert verify_password("OldAccountPassword1!", legacy_hash) is True
    assert verify_password("WrongPassword", legacy_hash) is False


def test_malformed_hash_fails_closed():
    assert verify_password("anything", "not-a-real-hash") is False
    assert verify_password("anything", "") is False
