import hashlib
import random

# ruleid: python-weak-hash-algorithm
digest = hashlib.md5(b"password").hexdigest()
# ruleid: python-weak-hash-algorithm
other = hashlib.new("sha1", b"x")
# ruleid: python-random-for-secret
session_token = "".join(random.choice("abc") for _ in range(16))
