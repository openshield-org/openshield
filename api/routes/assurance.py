"""Provider-assurance routes for infrastructure that tenants cannot scan."""

import logging

from flask import Blueprint, jsonify

from api.services.physical_assurance import CatalogValidationError, get_physical_assurance_report
from api.services.data_link_assurance import get_data_link_assurance_report
from api.services.network_layer_assurance import get_network_layer_assurance_report


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


@assurance_bp.get("/api/assurance/data-link-layer")
def get_data_link_layer_assurance():
    """Return Azure public-cloud OSI Layer 2 responsibility and evidence coverage."""
    try:
        return jsonify(get_data_link_assurance_report())
    except CatalogValidationError as exc:
        logger.error("Data Link assurance catalog validation failed: %s", exc)
        return jsonify({"error": "Data Link assurance catalog is unavailable"}), 500
    except Exception as exc:
        logger.error("Failed to build Data Link assurance report: %s", exc)
        return jsonify({"error": "Data Link assurance report generation failed"}), 500


@assurance_bp.get("/api/assurance/network-layer")
def get_network_layer_assurance():
    """Return Azure public-cloud OSI Layer 3 responsibility and evidence coverage."""
    try:
        return jsonify(get_network_layer_assurance_report())
    except CatalogValidationError as exc:
        logger.error("Network Layer assurance catalog validation failed: %s", exc)
        return jsonify({"error": "Network Layer assurance catalog is unavailable"}), 500
    except Exception as exc:
        logger.error("Failed to build Network Layer assurance report: %s", exc)
        return jsonify({"error": "Network Layer assurance report generation failed"}), 500
