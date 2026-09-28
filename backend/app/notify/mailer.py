"""The mail port — a protocol and its null implementation, nothing that sends.

Phase 6 ships the seam the future recovery-by-mail flow will call, and no
client behind it (``tasks/phase6-survey.md`` §6.3): an ``SmtpMailer`` lands
WITH the flow that uses it, so no untested outbound code exists before then,
and ``DIOPTRA_MAIL_ENABLED=true`` refuses to boot (``core/config.py``).

Recorded now so the recovery task inherits it: that flow never applies to
the ``admin`` role (survey §6.2). An admin who loses their password is reset
by another admin, or by the bootstrap command when none is left.
"""

from __future__ import annotations

import logging
from typing import Protocol

logger = logging.getLogger("dioptra.notify")


class Mailer(Protocol):
    def send(self, *, to: str, subject: str, body: str) -> None:
        """Deliver one plain-text message to one operator-known address."""


class NullMailer:
    """The only implementation today: records that mail is off and drops the message.

    Logs the subject only — never the recipient or the body, which may one day
    carry a recovery token.
    """

    def send(self, *, to: str, subject: str, body: str) -> None:  # noqa: ARG002
        logger.info("mail disabled; message dropped: %s", subject[:120])


def get_mailer() -> Mailer:
    return NullMailer()
