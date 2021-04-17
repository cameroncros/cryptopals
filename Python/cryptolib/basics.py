import base64


def from_hex(buffer: bytes) -> bytes:
    return bytes.fromhex(buffer.decode("UTF-8"))


def to_hex(buffer: bytes) -> bytes:
    return buffer.hex().encode("UTF-8")


def from_b64(buffer: bytes):
    return base64.b64decode(buffer)


def to_b64(buffer: bytes):
    return base64.b64encode(buffer)
