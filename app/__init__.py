"""Flask application factory."""

import os

from flask import Flask, jsonify, redirect, request, send_from_directory

from config import Config
from app.extensions import db, limiter
from flask_talisman import Talisman
from flask_cors import CORS
from werkzeug.middleware.proxy_fix import ProxyFix


def create_app(config_object=Config):
    app = Flask(__name__, static_folder="static", template_folder="templates")
    app.config.from_object(config_object)

    # Behind a reverse proxy every request otherwise appears to come from the
    # proxy's IP, which would make per-IP rate limiting throttle all users as
    # one client. Only trust forwarded headers when told exactly how many
    # proxies sit in front (TRUST_PROXY_HOPS); the default of 0 ignores them.
    hops = app.config.get("TRUST_PROXY_HOPS", 0)
    if hops > 0:
        app.wsgi_app = ProxyFix(app.wsgi_app, x_for=hops, x_proto=hops, x_host=hops)

    # Ensure instance folder exists for SQLite file DB.
    instance_dir = os.path.join(os.path.dirname(os.path.dirname(__file__)), "instance")
    os.makedirs(instance_dir, exist_ok=True)

    db.init_app(app)
    limiter.init_app(app)

    # CORS is scoped to /api/* only (the dashboard templates served at "/" don't
    # need it) and to the storefront's own origin(s) -- never "*". The JWT is
    # sent as an Authorization header, not a cookie, so credentials support is
    # left off; that also means a stolen/misconfigured origin can't ride on the
    # user's cookies anyway.
    CORS(
        app,
        resources={r"/api/*": {"origins": app.config["CORS_ALLOWED_ORIGINS"]}},
        supports_credentials=False,
        allow_headers=["Content-Type", "Authorization"],
        methods=["GET", "POST", "OPTIONS"],
    )

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
    @app.before_request
    def _prefer_localhost():
        # Passkeys/security keys are bound to the name "localhost" and browsers
        # refuse them on a numeric address ("This is an invalid domain"). Send
        # anyone who opens the pages via 127.0.0.1 to the working address. The
        # API and health check are left alone so scripts and containers that
        # call 127.0.0.1 keep working.
        if (
            request.method == "GET"
            and request.host.split(":")[0] == "127.0.0.1"
            and not request.path.startswith("/api/")
            and request.path != "/health"
        ):
            host = request.host.replace("127.0.0.1", "localhost", 1)
            return redirect(f"{request.scheme}://{host}{request.full_path.rstrip('?')}", code=302)

    # API callers (the dashboard and the storefront) parse JSON, so rate-limit and
    # crash responses must be JSON too -- the default HTML pages left them showing
    # a vague "failed" with no clue why.
    @app.errorhandler(429)
    def _too_many_requests(err):
        if request.path.startswith("/api/"):
            return jsonify(
                error="Too many attempts. Please wait a minute and try again.",
                limit=str(err.description),
            ), 429
        return err

    @app.errorhandler(500)
    def _server_error(err):
        if request.path.startswith("/api/"):
            return jsonify(
                error="The server hit an unexpected error. Please try again; "
                "if it keeps happening, check the MLPSAPS server log."
            ), 500
        return err

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
