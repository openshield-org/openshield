"""Flask application factory for the OpenShield REST API."""

import logging
import os

import jwt
from dotenv import load_dotenv
from flask import Flask, g, jsonify, request
from flask_cors import CORS

load_dotenv()

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s %(levelname)s %(name)s: %(message)s",
)
logger = logging.getLogger(__name__)

# Paths that do not require a JWT token
_PUBLIC_PATHS = {"/health", "/"}


def create_app() -> Flask:
    """Create and configure the Flask application.

    Returns a fully wired Flask app with:
    - CORS enabled for all origins
    - JWT authentication middleware on all non-public routes
    - Blueprints for findings, scans, score, and compliance
    - JSON error handlers for 400, 401, 403, 404, and 500
    """
    app = Flask(__name__)

    # ------------------------------------------------------------------ #
    # Configuration & Security                                             #
    # ------------------------------------------------------------------ #
    secret = os.environ.get("JWT_SECRET")
    if not secret:
        logger.warning("!!! SECURITY WARNING: JWT_SECRET NOT SET. USING INSECURE DEFAULT !!!")
        secret = "change-me-in-production"
    app.config["JWT_SECRET"] = secret

    # ------------------------------------------------------------------ #
    # CORS                                                                  #
    # ------------------------------------------------------------------ #
    allowed_origins = os.environ.get("ALLOWED_ORIGINS", "*").split(",")
    CORS(app, resources={r"/api/*": {"origins": allowed_origins}})

    # ------------------------------------------------------------------ #
    # JWT middleware                                                         #
    # ------------------------------------------------------------------ #

    @app.before_request
    def verify_jwt() -> None:
        """Validate the Bearer token on every non-public, non-OPTIONS request."""
        if request.method == "OPTIONS":
            return None
        if request.path in _PUBLIC_PATHS:
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
    from api.routes.compliance import compliance_bp
    from api.routes.findings import findings_bp
    from api.routes.scans import scans_bp
    from api.routes.score import score_bp

    app.register_blueprint(findings_bp)
    app.register_blueprint(scans_bp)
    app.register_blueprint(score_bp)
    app.register_blueprint(compliance_bp)

    # ------------------------------------------------------------------ #
    # Health check (public)                                                 #
    # ------------------------------------------------------------------ #

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

    logger.info("OpenShield API created — %d blueprints registered", len(app.blueprints))
    return app


if __name__ == "__main__":
    application = create_app()
    application.run(
        host="0.0.0.0",
        port=int(os.environ.get("PORT", 5000)),
        debug=os.environ.get("FLASK_DEBUG", "false").lower() == "true",
    )
