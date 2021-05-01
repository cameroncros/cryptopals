import math
import random
import unittest
from typing import Tuple

from libhannah.basics import from_b64, print_buffer
from libhannah.ssl import pkcs7_pad, pkcs7_unpad, dec_CBC, enc_CBC, enc_ECB, AES_BLOCK_SIZE, detect_ECB, dec_ECB
from libhannah.xor import xor

key = random.randbytes(16)
iv = random.randbytes(16)


def oracle11(buffer: bytes) -> tuple[bytes, bool]:
    prepend = random.randbytes(random.randint(5, 10))
    append = random.randbytes(random.randint(5, 10))
    mode = random.randint(0, 1)
    if mode:
        return enc_ECB(prepend + buffer + append, key), bool(mode)
    else:
        iv = random.randbytes(16)
        return enc_CBC(prepend + buffer + append, key, iv), bool(mode)


def defeat_ecb_oracle(oracle: '(buffer: bytes) -> bytes') -> Tuple[bytes, int, int]:
    def detect_block_size():
        initial_size = len(oracle(b'A'))
        for i in range(2, 64):
            size = len(oracle(b'A' * i))
            if size > initial_size:
                return size - initial_size

    block_size = detect_block_size()

    def detect_initial_offset():
        for i in range(0, 64):
            ciphertext = oracle((b'a' * i) + (b'B' * block_size * 2))
            for j in range(0, len(ciphertext) - block_size, block_size):
                if ciphertext[j:j + block_size] == ciphertext[j + block_size:j + 2 * block_size]:
                    return j - i

    initial_offset = detect_initial_offset()

    initial_size = math.ceil(len(oracle(b'')) / block_size) * block_size
    block_start = initial_size - block_size
    block_end = block_start + block_size
    found = b''
    for i in range(initial_size - 1 - initial_offset, initial_offset, -1):
        encoded = oracle(b'A' * i)

        for j in range(256):
            test_enc = oracle(b'A' * i + found + bytes([j]))
            if encoded[block_start:block_end] == test_enc[block_start:block_end]:
                found += bytes([j])
                break
        else:
            # no more bytes to discover
            break
    return found, block_size, initial_offset


def oracle12(buffer: bytes) -> bytes:
    unknown = from_b64(b'Um9sbGluJyBpbiBteSA1LjAKV2l0aCBteSByYWctdG9wIGRvd24gc28gbXkg'
                       b'aGFpciBjYW4gYmxvdwpUaGUgZ2lybGllcyBvbiBzdGFuZGJ5IHdhdmluZyBq'
                       b'dXN0IHRvIHNheSBoaQpEaWQgeW91IHN0b3A/IE5vLCBJIGp1c3QgZHJvdmUg'
                       b'YnkK')
    return enc_ECB(buffer + unknown, key)


def profile_for(email: bytes) -> bytes:
    assert (b'&' not in email)
    assert (b'=' not in email)
    return enc_ECB(b"email=%s&uid=10&role=user" % email, key)


def decrypt_profile(profile: bytes) -> bytes:
    return dec_ECB(profile, key)


def encrypt_data16(data: bytes) -> bytes:
    assert (b';' not in data)
    assert (b'=' not in data)
    prepend = b"comment1=cooking%20MCs;userdata="
    postpend = b";comment2=%20like%20a%20pound%20of%20bacon"
    return enc_CBC(prepend + data + postpend, key, iv)


def check_admin16(data) -> Tuple[bool, bytes]:
    decrypted = dec_CBC(data, key, iv)
    return b';admin=true;' in decrypted, decrypted


prepend = random.randbytes(random.randint(0, 16))


def oracle14(buffer: bytes) -> bytes:
    unknown = from_b64(b'Um9sbGluJyBpbiBteSA1LjAKV2l0aCBteSByYWctdG9wIGRvd24gc28gbXkg'
                       b'aGFpciBjYW4gYmxvdwpUaGUgZ2lybGllcyBvbiBzdGFuZGJ5IHdhdmluZyBq'
                       b'dXN0IHRvIHNheSBoaQpEaWQgeW91IHN0b3A/IE5vLCBJIGp1c3QgZHJvdmUg'
                       b'YnkK')
    return enc_ECB(prepend + buffer + unknown, key)


class CryptoPalsS1(unittest.TestCase):
    def test_challenge9(self):
        """
        pkcs7 padding
        """
        self.assertEqual(
            b'YELLOW SUBMARINE\x04\x04\x04\x04',
            pkcs7_pad(b'YELLOW SUBMARINE', block_size=20))
        self.assertEqual(
            b'YELLOW SUBMARINE',
            pkcs7_unpad(b'YELLOW SUBMARINE\x04\x04\x04\x04'))

    def test_challenge10(self):
        """
        Decrypt CBC
        """
        with open('../../C/tests/10.txt', 'rb') as f:
            encrypted = from_b64(f.read())
        decrypted = pkcs7_unpad(dec_CBC(encrypted, b'YELLOW SUBMARINE', b'\x00' * 16))
        self.assertTrue(decrypted.decode('UTF-8').startswith("I'm back and I'm ringin' the bell \n"
                                                             "A rockin' on the mike while the fly girls yell \n"
                                                             "In ecstasy in the back of me \n"))
        self.assertTrue(decrypted.decode('UTF-8').endswith("Play that funky music A little louder now \n"
                                                           "Play that funky music, white boy Come on, Come on, Come on \n"
                                                           "Play that funky music \n"))
        reencrypted = enc_CBC(decrypted, b'YELLOW SUBMARINE', b'\x00' * 16)
        self.assertEqual(encrypted, reencrypted)

    def test_challenge11(self):
        """
        Detect which mode an oracle is using
        """
        for _ in range(1000):
            ciphertext, mode = oracle11(b'A' * AES_BLOCK_SIZE * 4)
            self.assertEqual(mode, detect_ECB(ciphertext))

    def test_challenge12(self):
        """
        Defeat ECB
        """
        found, block_size, initial_offset = defeat_ecb_oracle(oracle12)
        self.assertEqual(AES_BLOCK_SIZE, block_size)
        self.assertEqual(0, initial_offset)
        self.assertEqual(b"Rollin' in my 5.0\n"
                         b"With my rag-top down so my hair can blow\n"
                         b"The girlies on standby waving just to say hi\n"
                         b"Did you stop? No, I just drove by\n\x01", found)

    def test_challenge13(self):
        """
        Construct ECB using oracle
        """
        self.assertEqual(b'email=crypto@test.com&uid=10&role=user',
                         decrypt_profile(profile_for(b"crypto@test.com")))
        # Get block aligned "email="(6) + email + "&uid=10&role="(13), email must be 32 - 6-13 = 13
        block_aligned_email = profile_for(b"abc@gmail.com")  # First 2 blocks are valuable.
        # Get block containig "admin" by itself
        block_aligned_admin = profile_for(b'A' * 10 + pkcs7_pad(b'admin', 16))  # 2nd block is valuable

        crafted_profile = block_aligned_email[0:AES_BLOCK_SIZE * 2] + block_aligned_admin[
                                                                      AES_BLOCK_SIZE:2 * AES_BLOCK_SIZE]
        self.assertEqual(b'email=abc@gmail.com&uid=10&role=admin',
                         decrypt_profile(crafted_profile))

    def test_challenge14(self):
        """
        Defeat ECB oracle with a prepended offset
        """
        found, block_size, initial_offset = defeat_ecb_oracle(oracle14)
        self.assertEqual(AES_BLOCK_SIZE, block_size)
        self.assertEqual(len(prepend), initial_offset)
        self.assertEqual(b"Rollin' in my 5.0\n"
                         b"With my rag-top down so my hair can blow\n"
                         b"The girlies on standby waving just to say hi\n"
                         b"Did you stop? No, I just drove by\n\x01", found)

    def test_challenge15(self):
        """
        Validate if PKCS7 padding
        """
        self.assertEqual(b"ICE ICE BABY",
                         pkcs7_unpad(b"ICE ICE BABY\x04\x04\x04\x04"))
        with self.assertRaises(Exception):
            pkcs7_unpad(b'ICE ICE BABY\x05\x05\x05\x05')
        with self.assertRaises(Exception):
            pkcs7_unpad(b'ICE ICE BABY\x01\x02\x03\x04')

    def test_challenge16(self):
        data = encrypt_data16(b'a')
        is_admin, _ = check_admin16(data)
        self.assertFalse(is_admin)

        # Really not sure this is the correct solution, but put a huge buffer of 'a' into the comment,
        # Then, xor in the text we want to appear (xor'd against 'a'), make sure it gets xor'd into the a section
        # The decrypted buffer gets a bit mangled, but ;admin=true; does appear as well.
        data = encrypt_data16(b'a'*256)
        modified_data = xor(data, b'\x00'*128 + xor(b';admin=true;c=', b'a') + b'\x00' * 1024)
        is_admin, decrypted = check_admin16(modified_data)
        print_buffer(decrypted)
        self.assertTrue(is_admin)
