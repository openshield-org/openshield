"""Flask application factory for the OpenShield REST API."""

import logging
import os

import jwt
from dotenv import load_dotenv
from flask import Flask, g, jsonify, request
from flask_cors import CORS

from api.models.finding import DatabaseManager

load_dotenv()

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s %(levelname)s %(name)s: %(message)s",
)
logger = logging.getLogger(__name__)

# Paths that do not require a JWT token
# All GET requests are public — the dashboard is a public demo of seeded data.
# POST endpoints (scan trigger, AI) remain JWT-protected.
def _is_public_get(path: str) -> bool:
    if path in ("/", "/health"):
        return True
    return path.startswith("/api/")

_INSECURE_JWT_DEFAULT = "change-me-in-production"
_MIN_JWT_SECRET_LENGTH = 32
_GENERATE_CMD = "python -c \"import secrets; print(secrets.token_urlsafe(32))\""


def _is_production() -> bool:
    return (
        os.environ.get("OPENSHIELD_ENV", "").lower() == "production"
        or os.environ.get("RENDER", "").lower() == "true"
    )


def _is_development() -> bool:
    return (
        os.environ.get("OPENSHIELD_ENV", "").lower() == "development"
        or os.environ.get("FLASK_DEBUG", "").lower() == "true"
    )


def _resolve_jwt_secret() -> str:
    """Return the JWT signing secret, enforcing production safety rules.

    Production (OPENSHIELD_ENV=production or RENDER=true): raises RuntimeError
    if the secret is missing, is the known insecure default, or is shorter than
    32 characters.  All other environments allow the default with a loud warning.
    """
    jwt_key = os.environ.get("JWT_SECRET", "")
    if _is_production():
        if not jwt_key:
            raise RuntimeError(
                "FATAL: JWT_SECRET is not set. "
                "Production deployments require a strong, unique JWT_SECRET. "
                f"Generate one with: {_GENERATE_CMD}"
            )
        if jwt_key == _INSECURE_JWT_DEFAULT:
            raise RuntimeError(
                "FATAL: JWT_SECRET is set to the insecure default value. "
                "Production deployments must use a unique secret. "
                f"Generate one with: {_GENERATE_CMD}"
            )
        if len(jwt_key) < _MIN_JWT_SECRET_LENGTH:
            raise RuntimeError(
                f"FATAL: JWT_SECRET must be at least {_MIN_JWT_SECRET_LENGTH} characters. "
                f"Generate one with: {_GENERATE_CMD}"
            )
        return jwt_key

    if not jwt_key:
        logger.warning(
            "!!! SECURITY WARNING: JWT_SECRET NOT SET. "
            "Using insecure default for local development only. "
            "Set OPENSHIELD_ENV=production (or RENDER=true) to enforce a strong "
            "secret and block startup when it is missing. !!!"
        )
        return _INSECURE_JWT_DEFAULT

    return jwt_key


def create_app() -> Flask:
    """Create and configure the Flask application.

    Returns a fully wired Flask app with:
    - CORS enabled for all origins
    - JWT authentication middleware on all non-public routes
    - Blueprints for findings, scans, score, and compliance
    - JSON error handlers for 400, 401, 403, 404, and 500
    - Global database connection teardown
    """
    app = Flask(__name__)

    # ------------------------------------------------------------------ #
    # Configuration & Security                                             #
    # ------------------------------------------------------------------ #
    app.config["JWT_SECRET"] = _resolve_jwt_secret()

    # ------------------------------------------------------------------ #
    # CORS                                                                  #
    # ------------------------------------------------------------------ #
    allowed_origins_raw = os.environ.get("ALLOWED_ORIGINS", "*")
    if allowed_origins_raw == "*":
        logger.warning(
            "!!! SECURITY WARNING: ALLOWED_ORIGINS NOT SET. DEFAULTING TO '*' !!! "
            "For production deployments, set this to your specific frontend domain(s)."
        )
    allowed_origins = allowed_origins_raw.split(",")
    CORS(app, resources={r"/*": {"origins": allowed_origins}})

    # ------------------------------------------------------------------ #
    # Database Management                                                   #
    # ------------------------------------------------------------------ #
    with app.app_context():
        db = DatabaseManager()
        db.run_migrations()

    @app.teardown_appcontext
    def close_db(error=None):
        """Ensure the database connection is closed after the request."""
        for key in ("db", "db_conn"):
            db = g.pop(key, None)
            if db is None:
                continue
            try:
                if hasattr(db, "conn") and db.conn is not None:
                    db.conn.close()
                    logger.debug("Database connection closed gracefully")
            except Exception as exc:
                logger.error("Error closing database connection: %s", exc)

    # ------------------------------------------------------------------ #
    # JWT middleware                                                         #
    # ------------------------------------------------------------------ #

    @app.before_request
    def verify_jwt() -> None:
        """Validate the Bearer token on every non-public, non-OPTIONS request."""
        if request.method == "OPTIONS":
            return None
        if request.method == "GET" and _is_public_get(request.path):
            return None

        auth = request.headers.get("Authorization", "")
        if not auth.startswith("Bearer "):
            return jsonify({"error": "Missing or malformed Authorization header"}), 401

        token = auth.split(" ", 1)[1]
        try:
            payload = jwt.decode(
                token,
                app.config["JWT_SECRET"],
                algorithms=["HS256"],
            )
            g.user = payload
        except jwt.ExpiredSignatureError:
            return jsonify({"error": "Token has expired"}), 401
        except jwt.InvalidTokenError as exc:
            return jsonify({"error": f"Invalid token: {exc}"}), 401

        return None

    # ------------------------------------------------------------------ #
    # Blueprints                                                            #
    # ------------------------------------------------------------------ #
    from api.routes.ai import ai_bp
    from api.routes.compliance import compliance_bp
    from api.routes.drift import drift_bp
    from api.routes.findings import findings_bp
    from api.routes.prioritization import prioritization_bp
    from api.routes.resources import resources_bp
    from api.routes.scans import scans_bp
    from api.routes.score import score_bp

    app.register_blueprint(ai_bp)
    app.register_blueprint(compliance_bp)
    app.register_blueprint(drift_bp)
    app.register_blueprint(findings_bp)
    app.register_blueprint(prioritization_bp)
    app.register_blueprint(resources_bp)
    app.register_blueprint(scans_bp)
    app.register_blueprint(score_bp)

    # ------------------------------------------------------------------ #
    # Routes (public)                                                      #
    # ------------------------------------------------------------------ #

    @app.get("/")
    def index():
        return jsonify({
            "message": "Welcome to the OpenShield REST API",
            "version": "1.0.0",
            "docs": "/docs",
            "status": "online"
        })

    @app.get("/health")
    def health():
        return jsonify({"status": "ok"})

    # ------------------------------------------------------------------ #
    # Error handlers                                                        #
    # ------------------------------------------------------------------ #

    @app.errorhandler(400)
    def bad_request(exc):
        return jsonify({"error": "Bad request", "detail": str(exc)}), 400

    @app.errorhandler(401)
    def unauthorized(exc):
        return jsonify({"error": "Unauthorized"}), 401

    @app.errorhandler(403)
    def forbidden(exc):
        return jsonify({"error": "Forbidden"}), 403

    @app.errorhandler(404)
    def not_found(exc):
        return jsonify({"error": "Not found"}), 404

    @app.errorhandler(500)
    def internal_error(exc):
        logger.error("Unhandled exception: %s", exc)
        return jsonify({"error": "Internal server error"}), 500

    logger.info("OpenShield API created - %d blueprints registered", len(app.blueprints))
    return app


application = create_app()

if __name__ == "__main__":
    application.run(
        host="0.0.0.0",
        port=int(os.environ.get("PORT", 5000)),
        debug=os.environ.get("FLASK_DEBUG", "false").lower() == "true",
    )
