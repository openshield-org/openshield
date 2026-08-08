"""Provider-assurance routes for infrastructure that tenants cannot scan."""

import logging

from flask import Blueprint, jsonify

from api.services.physical_assurance import CatalogValidationError, get_physical_assurance_report


assurance_bp = Blueprint("assurance", __name__)
logger = logging.getLogger(__name__)


@assurance_bp.get("/api/assurance/physical-layer")
def get_physical_layer_assurance():
    """Return Azure public-cloud OSI Layer 1 responsibility and evidence coverage."""
    try:
        return jsonify(get_physical_assurance_report())
    except CatalogValidationError as exc:
        logger.error("Physical assurance catalog validation failed: %s", exc)
        return jsonify({"error": "Physical assurance catalog is unavailable"}), 500
    except Exception as exc:
        logger.error("Failed to build physical assurance report: %s", exc)
        return jsonify({"error": "Physical assurance report generation failed"}), 500
