from app.security.jwt_utils import decode_token, create_access_token


def test_token_still_verifies_with_current_secret(app):
    """Baseline: with no rotation in progress, tokens verify normally."""
    with app.app_context():
        token, _jti = create_access_token(user_id=1)
        payload = decode_token(token)
        assert payload["sub"] == 1


def test_token_signed_with_previous_secret_still_verifies_during_rotation(app):
    """
    Simulates a secret rotation: a token signed with the OLD secret should
    still verify as long as JWT_SECRET_KEY_PREVIOUS is set to that old value,
    even though JWT_SECRET_KEY has already moved on to a new one.
    """
    with app.app_context():
        # Issue a token under the "old" secret.
        app.config["JWT_SECRET_KEY"] = "old-secret-123"
        app.config["JWT_SECRET_KEY_PREVIOUS"] = None
        old_token, _jti = create_access_token(user_id=42)

        # Rotate: new secret becomes current, old one becomes "previous".
        app.config["JWT_SECRET_KEY"] = "new-secret-456"
        app.config["JWT_SECRET_KEY_PREVIOUS"] = "old-secret-123"

        # The token issued under the old secret must still decode successfully.
        payload = decode_token(old_token)
        assert payload["sub"] == 42

        # And a brand-new token, issued after rotation, uses the new secret.
        new_token, _jti = create_access_token(user_id=42)
        new_payload = decode_token(new_token)
        assert new_payload["sub"] == 42


def test_token_rejected_once_previous_secret_is_dropped(app):
    """Once JWT_SECRET_KEY_PREVIOUS is cleared (rotation window closed), a
    token signed with that old secret must be rejected again."""
    import jwt as pyjwt
    import pytest

    with app.app_context():
        app.config["JWT_SECRET_KEY"] = "old-secret-789"
        app.config["JWT_SECRET_KEY_PREVIOUS"] = None
        old_token, _jti = create_access_token(user_id=7)

        # Rotate fully: old secret is no longer accepted at all.
        app.config["JWT_SECRET_KEY"] = "new-secret-999"
        app.config["JWT_SECRET_KEY_PREVIOUS"] = None

        with pytest.raises(pyjwt.InvalidSignatureError):
            decode_token(old_token)
