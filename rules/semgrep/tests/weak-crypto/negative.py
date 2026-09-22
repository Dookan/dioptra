import hashlib
import random
import secrets

# ok: python-weak-hash-algorithm
digest = hashlib.sha256(b"data").hexdigest()
# ok: python-random-for-secret
session_token = secrets.token_urlsafe(32)
# ok: python-random-for-secret
delay = random.uniform(0, 1)
