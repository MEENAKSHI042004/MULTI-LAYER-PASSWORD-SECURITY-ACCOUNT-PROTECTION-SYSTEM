"""Flask application factory."""

import os

from flask import Flask, send_from_directory

from config import Config
from app.extensions import db, limiter
from flask_talisman import Talisman


def create_app(config_object=Config):
    app = Flask(__name__, static_folder="static", template_folder="templates")
    app.config.from_object(config_object)

    # Ensure instance folder exists for SQLite file DB.
    instance_dir = os.path.join(os.path.dirname(os.path.dirname(__file__)), "instance")
    os.makedirs(instance_dir, exist_ok=True)

    db.init_app(app)
    limiter.init_app(app)
    Talisman(
        app,
        force_https=False,
        strict_transport_security=True,
        session_cookie_secure=False,
        content_security_policy={
            'default-src': "'self'",
            'script-src': "'self'",
            'style-src': "'self' 'unsafe-inline' https://fonts.googleapis.com",
            'style-src-elem': "'self' 'unsafe-inline' https://fonts.googleapis.com",
            'font-src': "'self' https://fonts.gstatic.com",
        },
    )

    from app.routes.auth import auth_bp
    from app.routes.admin import admin_bp
    app.register_blueprint(auth_bp)
    app.register_blueprint(admin_bp)

    with app.app_context():
        db.create_all()
        _seed_admin(app)

    @app.route("/")
    def dashboard():
        return send_from_directory(app.template_folder, "index.html")

    @app.route("/health")
    def health():
        return {"status": "ok"}, 200

    return app


def _seed_admin(app):
    """Create a default admin account on first run, from env vars if provided."""
    from app.models import User
    from app.security.hashing import hash_password

    if User.query.filter_by(is_admin=True).first():
        return

    admin_username = os.environ.get("SEED_ADMIN_USERNAME", "admin")
    admin_email = os.environ.get("SEED_ADMIN_EMAIL", "admin@example.com")
    admin_password = os.environ.get("SEED_ADMIN_PASSWORD", "ChangeMe!2026")

    admin = User(
        username=admin_username,
        email=admin_email,
        password_hash=hash_password(admin_password),
        is_admin=True,
    )
    db.session.add(admin)
    db.session.commit()
    app.logger.info(
        "Seeded default admin '%s'. CHANGE THIS PASSWORD IMMEDIATELY in any real deployment.",
        admin_username,
    )
