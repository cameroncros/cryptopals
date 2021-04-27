import base64


def from_hex(buffer: bytes) -> bytes:
    return bytes.fromhex(buffer.decode("UTF-8"))


def to_hex(buffer: bytes) -> bytes:
    return buffer.hex().encode("UTF-8")


def from_b64(buffer: bytes):
    return base64.b64decode(buffer)


def to_b64(buffer: bytes):
    return base64.b64encode(buffer)

def print_buffer(buffer: bytes):
    i = 0
    for byte in buffer:
        print("%02x " % byte, end='')
        i += 1
        if i % 16 == 0:
            print()
