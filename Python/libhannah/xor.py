import struct


def xor(buffer1: bytes, buffer2: bytes) -> bytes:
    output = b''
    for i in range(len(buffer1)):
        output += bytes([buffer1[i] ^ buffer2[i % len(buffer2)]])
    return output
