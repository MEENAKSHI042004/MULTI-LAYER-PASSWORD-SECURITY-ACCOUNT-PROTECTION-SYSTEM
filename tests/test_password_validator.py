from app.security.password_validator import validate_password_strength


def test_fallback_blocks_common_password_when_breach_check_is_down(app, monkeypatch):
    monkeypatch.setattr('app.security.password_validator.check_pwned', lambda pw: -1)
    with app.app_context():
        errors = validate_password_strength('password1')
    assert any('common breach lists' in e for e in errors)


def test_strong_password_still_accepted_when_breach_check_is_down(app, monkeypatch):
    monkeypatch.setattr('app.security.password_validator.check_pwned', lambda pw: -1)
    with app.app_context():
        assert validate_password_strength('Tr1cky!Unique#Phrase') == []
        