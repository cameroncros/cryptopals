import math
import random
import unittest
from typing import Tuple

from libhannah.basics import from_b64, to_hex, to_b64
from libhannah.ssl import pkcs7_pad, pkcs7_unpad, dec_CBC, enc_CBC, enc_ECB, AES_BLOCK_SIZE, detect_ECB, dec_ECB
from libhannah.xor import xor

oracle_key = random.randbytes(16)
oracle_iv = random.randbytes(16)
oracle17_plaintexts = [
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


def oracle17() -> Tuple[bytes, bytes]:
    chosen = oracle17_plaintexts[random.randint(0, len(oracle17_plaintexts) - 1)]
    #chosen = oracle17_plaintexts[1]
    print("Plaintext: %s" % from_b64(chosen))
    return enc_CBC(from_b64(chosen), oracle_key, oracle_iv), oracle_iv


def validate17(ciphertext: bytes, iv: bytes) -> bool:
    decrypted = dec_CBC(ciphertext, oracle_key, iv)
    # noinspection PyBroadException
    try:
        pkcs7_unpad(decrypted)
        return True
    except Exception as _:
        return False


def CBC_padding_attack_decode_block(validator: '(ciphertext: bytes, cipher_iv: bytes) -> bool',
                                    iv: bytes,
                                    block: bytes) -> bytes:

    # Detect if the block is already padded
    start_padding = 0
    if validator(block, iv):
        while start_padding < AES_BLOCK_SIZE:
            start_padding += 1
            corrupted_iv = xor(iv, b'\xff', offset=AES_BLOCK_SIZE - start_padding - 1, repeat=False)
            if validator(block, corrupted_iv):
                break

    # Detect remaining bytes by elimination
    known_block = bytes([start_padding]) * start_padding
    for i in range(AES_BLOCK_SIZE - len(known_block), 0, -1):
        desired_padding = pkcs7_pad(b'\x00' * (i - 1))
        for j in range(0, 256):
            guess = bytes([j])
            guess_plain_text = (b'\x00' * (i - 1)) + guess + known_block
            corrupted_iv = xor(xor(iv, desired_padding), guess_plain_text)
            if validator(block, corrupted_iv):
                known_block = guess + known_block
                break
        else:
            raise Exception("Failed to decode byte")
    return known_block


def CBC_padding_attack(oracle: '() -> bytes',
                       validator: '(ciphertext: bytes, cipher_iv: bytes) -> bool') -> bytes:
    encrypted, enc_iv = oracle()

    known = b''
    block_pos = 0
    start_iv = enc_iv
    while block_pos < len(encrypted):
        target_block = encrypted[block_pos:block_pos + AES_BLOCK_SIZE]
        known += CBC_padding_attack_decode_block(validator,
                                                 start_iv,
                                                 target_block)
        print("Currently Solved: %s" % known)
        start_iv = encrypted[block_pos:block_pos + AES_BLOCK_SIZE]
        block_pos += AES_BLOCK_SIZE
    return known


class CryptoPalsS1(unittest.TestCase):
    def test_challenge17(self):
        """
        CBC Padding Oracle
        """
        for i in range(15):
            decrypted = CBC_padding_attack(oracle17, validate17)
            self.assertIn(to_b64(pkcs7_unpad(decrypted)), oracle17_plaintexts)
