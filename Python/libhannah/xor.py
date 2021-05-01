import struct


def xor(buffer1: bytes, buffer2: bytes, offset: int = 0, repeat: bool = True) -> bytes:
    """
    XOR a set of bytes with another set.
    :param buffer1: The base set of bytes, consider this the starting point
    :param buffer2: The bytes to XOR into the first buffer, bytes over the length of buffer1 - offset are unused.
    :param offset: The starting offset.
    :param repeat: When true, repeatedly uses the buffer2
    :return: The XOR'd output.
    """
    output = b''
    for i in range(len(buffer1)):
        if i < offset:  # Pre-offset
            output += bytes([buffer1[i]])
        elif repeat or i < offset + len(buffer2): # Repeating, or within first pass
            output += bytes([buffer1[i] ^ buffer2[(i-offset) % len(buffer2)]])
        else:  # Not repeating, and copying remaining bytes
            output += bytes([buffer1[i]])
    return output
