import random
import unittest
from datetime import datetime, timedelta
from typing import Tuple

from libhannah.basics import from_b64, to_b64, print_buffer
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

def encrypt_data26(data: bytes) -> bytes:
    assert (b';' not in data)
    assert (b'=' not in data)
    prepend = b"comment1=cooking%20MCs;userdata="
    postpend = b";comment2=%20like%20a%20pound%20of%20bacon"
    return enc_CTR(prepend + data + postpend, key, nonce)


def check_admin26(data) -> Tuple[bool, bytes]:
    decrypted = dec_CTR(data, key, nonce)
    return b';admin=true;' in decrypted, decrypted


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

    def test_challenge26(self):
        """
        CTR Bitflipping
        """
        data = encrypt_data26(b'a')
        is_admin, _ = check_admin26(data)
        self.assertFalse(is_admin)

        # Really not sure this is the correct solution, but put a huge buffer of 'a' into the comment,
        # Then, xor in the text we want to appear (xor'd against 'a'), make sure it gets xor'd into the a section
        # The decrypted buffer gets a bit mangled, but ;admin=true; does appear as well.
        data = encrypt_data26(b'a'*256)
        modified_data = xor(data, b'\x00'*128 + xor(b';admin=true;c=', b'a') + b'\x00' * 1024)
        is_admin, decrypted = check_admin26(modified_data)
        print_buffer(decrypted)
        self.assertTrue(is_admin)
