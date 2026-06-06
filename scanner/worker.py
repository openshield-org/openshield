"""
scanner/worker.py

Background worker process that polls the PostgreSQL database for pending
scans and executes them using ScanEngine.
"""

import logging
import os
import time
import traceback
from datetime import datetime, timezone

from api.models.finding import DatabaseManager
from scanner.engine import ScanEngine

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s %(levelname)s %(name)s: %(message)s",
)
logger = logging.getLogger("scanner.worker")

POLL_INTERVAL_SECONDS = 5


def run_worker():
    """Main worker loop."""
    db_url = os.environ.get("DATABASE_URL")
    if not db_url:
        logger.error("DATABASE_URL environment variable is not set")
        return

    db = DatabaseManager(db_url)
    logger.info("OpenShield Background Worker started. Polling every %ds", POLL_INTERVAL_SECONDS)

    while True:
        try:
            pending_scans = db.get_pending_scans()
            if not pending_scans:
                time.sleep(POLL_INTERVAL_SECONDS)
                continue

            for scan in pending_scans:
                scan_id = str(scan["scan_id"])
                subscription_id = scan["subscription_id"]
                
                logger.info("Starting scan %s for %s", scan_id, subscription_id)
                db.update_scan_status(scan_id, "running")

                try:
                    engine = ScanEngine(subscription_id)
                    result = engine.run_scan(scan_id)
                    
                    # Update result with completion metadata
                    result["completed_at"] = datetime.now(timezone.utc).isoformat()
                    result["status"] = "completed"
                    
                    db.save_scan(result)
                    logger.info("Successfully completed scan %s", scan_id)
                except Exception as exc:
                    error_msg = f"{str(exc)}\n{traceback.format_exc()}"
                    logger.error("Scan %s failed: %s", scan_id, error_msg)
                    db.update_scan_status(scan_id, "failed", error_message=str(exc))

        except Exception as exc:
            logger.error("Worker loop encountered an error: %s", exc)
            time.sleep(POLL_INTERVAL_SECONDS)


if __name__ == "__main__":
    run_worker()
