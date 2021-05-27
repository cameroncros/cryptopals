import math
import struct
from typing import List, Tuple

from libhannah.basics import to_hex


def rotate_left(value: int, num: int) -> int:
    return ((value << num) | (value >> (32 - num))) & 0xffffffff


def sha1(buffer: bytes, override_state: List[int] = None, override_length: int = 0) -> Tuple[bytes, List[int]]:
    """
    :param buffer: The bytes to hash
    :param h: Initial hash state
    :param override_length: Alternate length for has padding
    Note 1: All variables are unsigned 32-bit quantities and wrap modulo 232 when calculating, except for
        ml, the message length, which is a 64-bit quantity, and
        hh, the message digest, which is a 160-bit quantity.
    Note 2: All constants in this pseudo code are in big endian.
            Within each word, the most significant byte is stored in the leftmost byte position
    """
    # Initialize variables:
    h = [0x67452301,
         0xEFCDAB89,
         0x98BADCFE,
         0x10325476,
         0xC3D2E1F0]
    if override_state:
        h = override_state.copy()
    buffer += sha1_pad(len(buffer), override_length=override_length)
    # append the bit '1' to the message e.g. by adding 0x80 if message length is a multiple of 8 bits.
    # append 0 ≤ k < 64 bytes '0', such that the resulting message length in bits
    #    is congruent to −8 ≡ 56 (mod 64)
    # append ml, the original message length in bits, as a 64-bit big-endian integer.
    #    Thus, the total length is a multiple of 512 bits (64 bytes).
    assert (len(buffer) % 64 == 0)

    # Process the message in successive 64 byte chunks:
    # break message into 64 byte chunks
    for i in range(int(len(buffer) / 64)):
        chunk = buffer[i * 64:(i + 1) * 64]
        h = sha1_process_chunk(chunk, h)

    # Produce the final hash value (big-endian) as a 160-bit/20-byte number:
    hh = (h[0] << 128) | (h[1] << 96) | (h[2] << 64) | (h[3] << 32) | h[4]
    return to_hex(hh.to_bytes(byteorder='big', length=20)), h


def sha1_pad(buffer_len: int, override_length: int = None) -> bytes:
    ml = buffer_len
    # Pre-processing:
    dl = math.ceil((ml + 1 + 8) / 64) * 64
    pl = (dl - ml - 1 - 8)
    length = ml * 8
    if override_length:
        length = override_length * 8
    return b'\x80' + (b'\x00' * pl) + length.to_bytes(length=8, byteorder='big')


def sha1_process_chunk(chunk: bytes, h: List[int]) -> List[int]:
    # break chunk into sixteen 32-bit big-endian words w[i], 0 ≤ j ≤ 15
    w = [0] * 80
    for j in range(16):
        w[j] = int.from_bytes(chunk[j * 4:(j + 1) * 4], byteorder='big')
    # Message schedule: extend the sixteen 32-bit words into eighty 32-bit words:
    for j in range(16, 80):
        # Note 3: SHA-0 differs by not having this leftrotate.
        w[j] = rotate_left((w[j - 3] ^ w[j - 8] ^ w[j - 14] ^ w[j - 16]), 1) & 0xffffffff

    # Initialize hash value for this chunk:
    a = h[0]
    b = h[1]
    c = h[2]
    d = h[3]
    e = h[4]
    # Main loop:
    for j in range(80):
        if 0 <= j <= 19:
            f = ((b & c) | (~b & d)) & 0xffffffff
            k = 0x5A827999
        elif 20 <= j <= 39:
            f = (b ^ c ^ d) & 0xffffffff
            k = 0x6ED9EBA1
        elif 40 <= j <= 59:
            f = ((b & c) | (b & d) | (c & d)) & 0xffffffff
            k = 0x8F1BBCDC
        elif 60 <= j <= 79:
            f = (b ^ c ^ d) & 0xffffffff
            k = 0xCA62C1D6
        else:
            assert False

        temp = rotate_left(a, 5) + f + e + k + w[j] & 0xffffffff
        e = d
        d = c
        c = rotate_left(b, 30) & 0xffffffff
        b = a
        a = temp
    # Add this chunk's hash to result so far:
    h[0] = (h[0] + a) & 0xffffffff
    h[1] = (h[1] + b) & 0xffffffff
    h[2] = (h[2] + c) & 0xffffffff
    h[3] = (h[3] + d) & 0xffffffff
    h[4] = (h[4] + e) & 0xffffffff
    return h

def md4(buffer: bytes, override_state: List[int] = None, override_length: int = 0) -> Tuple[bytes, List[int]]:
    """
    :param buffer: The bytes to hash
    :param h: Initial hash state
    :param override_length: Alternate length for has padding
    :return Tuple containing the hash, and the internal state
    Note 1: All variables are unsigned 32-bit quantities and wrap modulo 232 when calculating, except for
        ml, the message length, which is a 64-bit quantity, and
        hh, the message digest, which is a 160-bit quantity.
    Note 2: All constants in this pseudo code are in big endian.
            Within each word, the most significant byte is stored in the leftmost byte position
    """
    # Initialize variables:
    h = [0x67452301,
         0xEFCDAB89,
         0x98BADCFE,
         0x10325476]
    if override_state:
        h = override_state.copy()
    buffer += md4_pad(len(buffer), override_length=override_length)
    assert (len(buffer) % 64 == 0)

    # Process the message in successive 64 byte chunks:
    # break message into 64 byte chunks
    for i in range(int(len(buffer) / 64)):
        chunk = buffer[i * 64:(i + 1) * 64]
        h = md4_process_chunk(chunk, h)

    hh_bytes = \
        h[0].to_bytes(byteorder='little', length=4) + \
        h[1].to_bytes(byteorder='little', length=4) + \
        h[2].to_bytes(byteorder='little', length=4) + \
        h[3].to_bytes(byteorder='little', length=4)
    return to_hex(hh_bytes), h


def md4_pad(buffer_len: int, override_length: int = None) -> bytes:
    ml = buffer_len
    # Pre-processing:
    dl = math.ceil((ml + 1 + 8) / 64) * 64
    pl = (dl - ml - 1 - 8)
    length = ml * 8
    if override_length:
        length = override_length * 8
    return b'\x80' + (b'\x00' * pl) + length.to_bytes(length=8, byteorder='little')


def md4_process_chunk(chunk: bytes, h_init: List[int]) -> List[int]:
    def F(x, y, z):
        return (x & y) | (~x & z)

    def G(x, y, z):
        return (x & y) | (x & z) | (y & z)

    def H(x, y, z):
        return x ^ y ^ z

    X = [0] * 16
    for j in range(16):
        X[j] = int.from_bytes(chunk[j * 4:(j + 1) * 4], byteorder='little')

    h = h_init.copy()

    # Round 1.
    Xi = [3, 7, 11, 19]
    for n in range(16):
        i, j, k, l = map(lambda x: x % 4, range(-n, -n + 4))
        K, S = n, Xi[n % 4]
        hn = h[i] + F(h[j], h[k], h[l]) + X[K]
        h[i] = rotate_left(hn & 0xFFFFFFFF, S)

    # Round 2.
    Xi = [3, 5, 9, 13]
    for n in range(16):
        i, j, k, l = map(lambda x: x % 4, range(-n, -n + 4))
        K, S = n % 4 * 4 + n // 4, Xi[n % 4]
        hn = h[i] + G(h[j], h[k], h[l]) + X[K] + 0x5A827999
        h[i] = rotate_left(hn & 0xFFFFFFFF, S)

    # Round 3.
    Xi = [3, 9, 11, 15]
    Ki = [0, 8, 4, 12, 2, 10, 6, 14, 1, 9, 5, 13, 3, 11, 7, 15]
    for n in range(16):
        i, j, k, l = map(lambda x: x % 4, range(-n, -n + 4))
        K, S = Ki[n], Xi[n % 4]
        hn = h[i] + H(h[j], h[k], h[l]) + X[K] + 0x6ED9EBA1
        h[i] = rotate_left(hn & 0xFFFFFFFF, S)

    return [((v + n) & 0xFFFFFFFF) for v, n in zip(h_init, h)]


