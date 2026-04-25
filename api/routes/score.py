"""Score route: overall security posture score."""

import os
from flask import Blueprint, jsonify

from api.models.finding import DatabaseManager

score_bp = Blueprint("score", __name__)


def _get_db() -> DatabaseManager:
    db = DatabaseManager(os.environ["DATABASE_URL"])
    db.connect()
    return db


@score_bp.get("/api/score")
def get_score():
    """Return the overall security posture score (0–100).

    Score calculation:
        Starts at 100. Deducts 10 per HIGH finding, 5 per MEDIUM, 2 per LOW.
        Floors at 0.
    """
    db = _get_db()
    score = db.get_score()
    return jsonify({"score": score, "max_score": 100})
