import hashlib
import hmac
import ssl

import jwt
from cryptography.hazmat.primitives.ciphers import algorithms


def digests(data: bytes, key: bytes) -> list[str]:
    # ruleid: crypto-inventory-py-hash
    strong = hashlib.sha256(data).hexdigest()
    # ruleid: crypto-inventory-py-weak-hash
    weak = hashlib.md5(data).hexdigest()
    # ruleid: crypto-inventory-py-hmac
    mac = hmac.new(key, data, hashlib.sha256).hexdigest()
    # ruleid: crypto-inventory-py-kdf
    derived = hashlib.pbkdf2_hmac("sha256", data, key, 100_000).hex()
    return [strong, weak, mac, derived]


def ciphers(key: bytes) -> tuple[object, object]:
    # ruleid: crypto-inventory-py-cipher
    modern = algorithms.AES(key)
    # ruleid: crypto-inventory-py-weak-cipher
    legacy = algorithms.TripleDES(key)
    return modern, legacy


def tokens(payload: dict[str, str], secret: str) -> str:
    # ruleid: crypto-inventory-py-signature
    return jwt.encode(payload, secret, algorithm="HS256")


def context() -> ssl.SSLContext:
    # ruleid: crypto-inventory-py-weak-protocol
    return ssl.SSLContext(ssl.PROTOCOL_TLSv1)
