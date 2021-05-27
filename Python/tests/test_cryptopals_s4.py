import random
import unittest
from datetime import datetime, timedelta
from typing import Tuple, List

from libhannah.basics import from_b64, to_b64, print_buffer, from_hex, to_hex
from libhannah.crypto import MT19937, untemper_MT19937, enc_MT19937, dec_MT19937
from libhannah.hash import sha1, rotate_left, sha1_pad
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


def validate_ascii(data: bytes):
    for byte in data:
        if int(byte) not in range(0, 128):
            raise Exception(b"Invalid ASCII: [%s]" % data)


def encrypt_data27(data: bytes) -> bytes:
    assert (b';' not in data)
    assert (b'=' not in data)
    prepend = b"comment1=cooking%20MCs;userdata="
    postpend = b";comment2=%20like%20a%20pound%20of%20bacon"
    plaintext = prepend + data + postpend
    validate_ascii(plaintext)

    return enc_CBC(plaintext, key, key)


def check_admin27(data) -> Tuple[bool, bytes]:
    decrypted = dec_CBC(data, key, key)
    validate_ascii(decrypted)
    return b';admin=true;' in decrypted, decrypted


def sha1_hmac(hashkey: bytes, data: bytes) -> bytes:
    return sha1(hashkey + data)


def hmac_message(message: bytes) -> bytes:
    return sha1_hmac(key, message)[0]


def validate_message(message: bytes, hmac: bytes) -> bool:
    return hmac_message(message) == hmac


def calc_sha1_state(sig: bytes) -> List[int]:
    sig = from_hex(sig)
    return [
        int.from_bytes(bytes=sig[0:4], byteorder='big'),
        int.from_bytes(bytes=sig[4:8], byteorder='big'),
        int.from_bytes(bytes=sig[8:12], byteorder='big'),
        int.from_bytes(bytes=sig[12:16], byteorder='big'),
        int.from_bytes(bytes=sig[16:20], byteorder='big')
    ]


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
        data = encrypt_data26(b'a' * 256)
        modified_data = xor(data, b'\x00' * 128 + xor(b';admin=true;c=', b'a') + b'\x00' * 1024)
        is_admin, decrypted = check_admin26(modified_data)
        print_buffer(decrypted)
        self.assertTrue(is_admin)

    def test_challenge27(self):
        """
        Defeat CBC where key==iv
        """
        try:
            encrypt_data27(b'\x00' * 15 + b'\xff')
        except Exception as e:
            message = e.args[0][16:-1]
            self.assertGreater(len(message), 16 * 3)

        encrypted = encrypt_data27(b'\x00' * 16)

        crafted_message = encrypted[0:16] + b'\x00' * 16 + encrypted[0:16]
        try:
            check_admin27(crafted_message)
        except Exception as e:
            message2 = e.args[0][16:-1]

        key_guess = xor(xor(message2[0:16], message2[16 * 2:16 * 3]), b'\x00' * 16)
        self.assertEqual(key, key_guess)

    def test_challenge28a(self):
        """
        left rotate implementation
        """
        self.assertEqual(0x45678123, rotate_left(0x12345678, 12))
        self.assertEqual(0x56781234, rotate_left(0x12345678, 16))
        self.assertEqual(0x67812345, rotate_left(0x12345678, 20))

    def test_challenge28b(self):
        """
        SHA1 implementation
        """
        self.assertEqual(b'da39a3ee5e6b4b0d3255bfef95601890afd80709',
                         sha1(b'')[0])
        self.assertEqual(b'2fd4e1c67a2d28fced849ee1bb76e7391b93eb12',
                         sha1(b'The quick brown fox jumps over the lazy dog')[0])
        self.assertEqual(b'de9f2c7fd25e1b3afad3e85a0bd17d9b100db4b3',
                         sha1(b'The quick brown fox jumps over the lazy cog')[0])

    def test_challenge28c(self):
        """
        SHA1 HMAC implementation
        """
        self.assertNotEqual(sha1_hmac(key, b'The quick brown fox jumps over the lazy dog'),
                            sha1_hmac(key, b'The quick brown fox jumps over the lazy cog'))

    def test_challenge29a(self):
        """
        SHA1 HMAC defeat - padding
        """
        string = b'comment1=cooking%20MCs;userdata=foo;comment2=%20like%20a%20pound%20of%20bacon'
        padding = sha1_pad(len(string) + len(key))
        self.assertEqual(b'\x80', padding[0])
        self.assertEqual(len(string) + len(key), int.from_bytes(bytes=padding[-8:], byteorder='big'))

    def test_challenge29b(self):
        """
        SHA1 HMAC defeat - state
        """
        signature, final_state = sha1_hmac(key,
                                           b'comment1=cooking%20MCs;userdata=foo;comment2=%20like%20a%20pound%20of%20bacon')

        state = calc_sha1_state(signature)
        self.assertEqual(final_state, state)

    def test_challenge29c(self):
        """
        SHA1 HMAC defeat - state
        """
        known_string = b'comment1=cooking%20MCs;userdata=foo;comment2=%20like%20a%20pound%20of%20bacon'
        known_sig = hmac_message(known_string)
        state = calc_sha1_state(known_sig)

        for key_len in range(30):
            padding = sha1_pad(key_len + len(known_string))
            override_length = key_len + len(known_string) + len(padding)
            crafted_sig, _ = sha1(b';admin=true',
                                  override_state=state,
                                  override_length=override_length + len(b';admin=true'))
            if validate_message(known_string + padding + b';admin=true', crafted_sig):
                self.assertEqual(key_len, len(key))
                break
        else:
            self.assertTrue(False)
