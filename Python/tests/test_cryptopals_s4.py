import random
import unittest
from datetime import datetime, timedelta
from typing import Tuple

from libhannah.basics import from_b64, to_b64
from libhannah.crypto import MT19937, untemper_MT19937, enc_MT19937, dec_MT19937
from libhannah.ssl import pkcs7_pad, pkcs7_unpad, dec_CBC, enc_CBC, AES_BLOCK_SIZE, dec_CTR, enc_CTR
from libhannah.tools import crack_xor
from libhannah.xor import xor

key = random.randbytes(16)
nonce = random.randbytes(8)


def edit_CTR(ciphertext: bytes, offset: int, new_text: bytes) -> bytes:
    decrypted = dec_CTR(ciphertext, key, nonce)
    new_plaintext = decrypted[0:offset] + new_text + decrypted[offset + len(new_text):]
    return enc_CTR(new_plaintext, key, nonce)


class CryptoPalsS4(unittest.TestCase):
    def test_challenge25(self):
        """
        CTR edit break
        """
        with open('../../C/tests/25.txt', 'rb') as f:
            data = from_b64(f.read())
            encrypted = enc_CTR(data, key, nonce)
            keystream = edit_CTR(encrypted, 0, b'\x00' * len(encrypted))
            decrypted = xor(encrypted, keystream)
            self.assertEqual(data, decrypted)
