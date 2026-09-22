"""RQ entry point for stage E7.

The verification starts containers, so it belongs to the worker — the only
process holding the Docker socket — exactly like the analysis pipeline. It
never raises: an attempt that cannot run is a recorded row with a reason, so
the developer sees what happened instead of a job that vanished.
"""

from __future__ import annotations

import logging
import uuid

from sqlalchemy import select

from app.analysis.models import Analysis
from app.auth.models import User
from app.core.config import get_settings
from app.db.session import get_session_factory
from app.workflow import verify

logger = logging.getLogger("dioptra.verify")


def run_verification_job(analysis_id: uuid.UUID | str, actor_username: str) -> None:
    identifier = uuid.UUID(str(analysis_id))
    settings = get_settings()
    with get_session_factory()() as db:
        analysis = db.get(Analysis, identifier)
        if analysis is None:
            logger.error("analysis %s vanished before the verification ran", identifier)
            return
        actor = db.scalars(select(User).where(User.username == actor_username)).first()
        if actor is None:
            logger.error("actor %s vanished before the verification ran", actor_username)
            return
        try:
            runs = verify.run_verification(
                db, settings, analysis=analysis, actor=actor, source_ip=None
            )
            logger.info("verified analysis=%s functions=%d", identifier, len(runs))
        except Exception:
            logger.exception("verification of analysis %s crashed", identifier)
            db.rollback()
            return
        db.commit()
