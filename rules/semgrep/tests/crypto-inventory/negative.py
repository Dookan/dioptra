import base64


def nothing_cryptographic(data: bytes) -> str:
    # ok: crypto-inventory-py-hash
    encoded = base64.b64encode(data).decode()
    # ok: crypto-inventory-py-cipher
    return encoded[::-1]
