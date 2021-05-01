import math
import random
import unittest
from typing import Tuple

from libhannah.basics import from_b64, print_buffer
from libhannah.ssl import pkcs7_pad, pkcs7_unpad, dec_CBC, enc_CBC, enc_ECB, AES_BLOCK_SIZE, detect_ECB, dec_ECB
from libhannah.xor import xor

key = random.randbytes(16)
iv = random.randbytes(16)


def oracle17() -> Tuple[bytes, bytes]:
    plaintexts = [
        b'MDAwMDAwTm93IHRoYXQgdGhlIHBhcnR5IGlzIGp1bXBpbmc=',
        b'MDAwMDAxV2l0aCB0aGUgYmFzcyBraWNrZWQgaW4gYW5kIHRoZSBWZWdhJ3MgYXJlIHB1bXBpbic=',
        b'MDAwMDAyUXVpY2sgdG8gdGhlIHBvaW50LCB0byB0aGUgcG9pbnQsIG5vIGZha2luZw==',
        b'MDAwMDAzQ29va2luZyBNQydzIGxpa2UgYSBwb3VuZCBvZiBiYWNvbg==',
        b'MDAwMDA0QnVybmluZyAnZW0sIGlmIHlvdSBhaW4ndCBxdWljayBhbmQgbmltYmxl',
        b'MDAwMDA1SSBnbyBjcmF6eSB3aGVuIEkgaGVhciBhIGN5bWJhbA==',
        b'MDAwMDA2QW5kIGEgaGlnaCBoYXQgd2l0aCBhIHNvdXBlZCB1cCB0ZW1wbw==',
        b'MDAwMDA3SSdtIG9uIGEgcm9sbCwgaXQncyB0aW1lIHRvIGdvIHNvbG8=',
        b'MDAwMDA4b2xsaW4nIGluIG15IGZpdmUgcG9pbnQgb2g=',
        b'MDAwMDA5aXRoIG15IHJhZy10b3AgZG93biBzbyBteSBoYWlyIGNhbiBibG93'
    ]
    chosen = plaintexts[random.randint(0, len(plaintexts) - 1)]
    return enc_CBC(from_b64(chosen), key, iv), iv


def validate17(ciphertext: bytes, cipher_iv: bytes) -> bool:
    decrypted = dec_CBC(ciphertext, key, cipher_iv)
    # noinspection PyBroadException
    try:
        pkcs7_unpad(decrypted)
        return True
    except Exception as _:
        return False


class CryptoPalsS1(unittest.TestCase):
    def test_challenge17(self):
        """
        CBC Padding Oracle
        """
        encrypted, enc_iv = oracle17()
        self.assertTrue(validate17(encrypted, enc_iv))

        real_padding = 0
        length = len(encrypted)
        for i in range(1, AES_BLOCK_SIZE):
            corrupting_block = (b'\x00' * (length - 2 * AES_BLOCK_SIZE)) + \
                               (b'\x00' * (AES_BLOCK_SIZE - i - 1)) + b'\xff' + (b'\x00' * i) + \
                               (b'\x00' * AES_BLOCK_SIZE)
            corrupted_text = xor(encrypted, corrupting_block)
            if validate17(corrupted_text, enc_iv):
                real_padding = i
                print("Real Padding is: %x" % real_padding)
                break
        else:
            self.assertTrue(False, "Failed to get the padded length")

        known = bytes([real_padding]) * real_padding
        for i in range(length - real_padding, 0, -1):
            expected_padding = bytes([length - i + 1]) * (length - i + 1)
            for j in range(0, 256):
                guess = b'\x00' * (i - AES_BLOCK_SIZE - 1) + \
                        bytes([j]) + known + \
                        b'\x00' * AES_BLOCK_SIZE
                corrupted_text = xor(guess, xor(encrypted, expected_padding))

                if validate17(corrupted_text, enc_iv):
                    known = bytes([j]) + known
                    print("Known (%i): %s" % (len(known), known))
                    break
            else:
                self.assertTrue(False, "Failed to find guess")
