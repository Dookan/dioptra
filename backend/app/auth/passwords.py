"""Password hashing (Argon2id) and the policy that guards it.

ASVS V2.4: memory-hard hashing with per-password salt. Parameters follow the
OWASP Password Storage Cheat Sheet's Argon2id baseline (19 MiB, t=2, p=1).
Revisit trigger: raise the cost when the API host gains RAM headroom, and let
``needs_rehash`` upgrade stored hashes transparently on the next login.
"""

from __future__ import annotations

from argon2 import PasswordHasher
from argon2.exceptions import InvalidHashError, VerificationError, VerifyMismatchError

from app.auth.errors import WeakPassword

MIN_PASSWORD_LENGTH = 12
MAX_PASSWORD_LENGTH = 256  # bound the work an unauthenticated caller can request

_hasher = PasswordHasher(
    time_cost=2,
    memory_cost=19 * 1024,  # KiB
    parallelism=1,
    hash_len=32,
    salt_len=16,
)

#: Verified against when the username is unknown, so a missing account costs
#: the same time as a wrong password (no user enumeration by timing).
_DUMMY_HASH = _hasher.hash("dioptra-dummy-password-for-constant-work")


def hash_password(password: str) -> str:
    """Hash a password after enforcing the length policy."""
    validate_password_policy(password)
    return _hasher.hash(password)


def verify_password(password_hash: str, password: str) -> bool:
    """Constant-work verification. Any malformed stored hash counts as a miss."""
    try:
        return _hasher.verify(password_hash, password)
    except (VerifyMismatchError, VerificationError, InvalidHashError):
        return False


def spend_dummy_verification(password: str) -> None:
    """Burn the same work as a real verification for an unknown username."""
    verify_password(_DUMMY_HASH, password)


def needs_rehash(password_hash: str) -> bool:
    """True when the stored hash predates the current cost parameters."""
    try:
        return _hasher.check_needs_rehash(password_hash)
    except InvalidHashError:
        return True


def validate_password_policy(password: str) -> None:
    """ASVS V2.1: length is the requirement; composition rules are not."""
    if not MIN_PASSWORD_LENGTH <= len(password) <= MAX_PASSWORD_LENGTH:
        raise WeakPassword(
            f"password length must be between {MIN_PASSWORD_LENGTH} and {MAX_PASSWORD_LENGTH}"
        )
