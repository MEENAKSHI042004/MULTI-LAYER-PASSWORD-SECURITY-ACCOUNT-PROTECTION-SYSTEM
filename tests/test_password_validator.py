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


def test_fail_closed_mode_rejects_when_breach_check_is_down(app, monkeypatch):
    app.config['BREACH_CHECK_FAIL_CLOSED'] = True
    monkeypatch.setattr('app.security.password_validator.check_pwned', lambda pw: -1)
    with app.app_context():
        errors = validate_password_strength('Tr1cky!Unique#Phrase')
    assert any('could not verify' in e.lower() for e in errors)