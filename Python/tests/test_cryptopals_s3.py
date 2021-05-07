import math
import random
import time
import unittest
from datetime import datetime, timedelta
from typing import Tuple

from libhannah.basics import from_b64, to_hex, to_b64, print_buffer
from libhannah.crypto import MT19937
from libhannah.ssl import pkcs7_pad, pkcs7_unpad, dec_CBC, enc_CBC, enc_ECB, AES_BLOCK_SIZE, detect_ECB, dec_ECB, \
    dec_CTR, enc_CTR
from libhannah.tools import crack_xor
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
    # chosen = oracle17_plaintexts[1]
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

    def test_challenge18(self):
        cipher = from_b64(b'L77na/nrFsKvynd6HzOoG7GHTLXsTVu9qvY/2syLXzhPweyyMTJULu/6/kXX0KSvoOLSFQ==')
        decrypted = dec_CTR(cipher, b'YELLOW SUBMARINE', b'\x00' * 8)
        self.assertEqual(b'Yo, VIP Let\'s kick it Ice, Ice, baby Ice, Ice, baby ', decrypted)

    def test_challenge19(self):
        plaintexts = [
            b'SSBoYXZlIG1ldCB0aGVtIGF0IGNsb3NlIG9mIGRheQ==',
            b'Q29taW5nIHdpdGggdml2aWQgZmFjZXM=',
            b'RnJvbSBjb3VudGVyIG9yIGRlc2sgYW1vbmcgZ3JleQ==',
            b'RWlnaHRlZW50aC1jZW50dXJ5IGhvdXNlcy4=',
            b'SSBoYXZlIHBhc3NlZCB3aXRoIGEgbm9kIG9mIHRoZSBoZWFk',
            b'T3IgcG9saXRlIG1lYW5pbmdsZXNzIHdvcmRzLA==',
            b'T3IgaGF2ZSBsaW5nZXJlZCBhd2hpbGUgYW5kIHNhaWQ=',
            b'UG9saXRlIG1lYW5pbmdsZXNzIHdvcmRzLA==',
            b'QW5kIHRob3VnaHQgYmVmb3JlIEkgaGFkIGRvbmU=',
            b'T2YgYSBtb2NraW5nIHRhbGUgb3IgYSBnaWJl',
            b'VG8gcGxlYXNlIGEgY29tcGFuaW9u',
            b'QXJvdW5kIHRoZSBmaXJlIGF0IHRoZSBjbHViLA==',
            b'QmVpbmcgY2VydGFpbiB0aGF0IHRoZXkgYW5kIEk=',
            b'QnV0IGxpdmVkIHdoZXJlIG1vdGxleSBpcyB3b3JuOg==',
            b'QWxsIGNoYW5nZWQsIGNoYW5nZWQgdXR0ZXJseTo=',
            b'QSB0ZXJyaWJsZSBiZWF1dHkgaXMgYm9ybi4=',
            b'VGhhdCB3b21hbidzIGRheXMgd2VyZSBzcGVudA==',
            b'SW4gaWdub3JhbnQgZ29vZCB3aWxsLA==',
            b'SGVyIG5pZ2h0cyBpbiBhcmd1bWVudA==',
            b'VW50aWwgaGVyIHZvaWNlIGdyZXcgc2hyaWxsLg==',
            b'V2hhdCB2b2ljZSBtb3JlIHN3ZWV0IHRoYW4gaGVycw==',
            b'V2hlbiB5b3VuZyBhbmQgYmVhdXRpZnVsLA==',
            b'U2hlIHJvZGUgdG8gaGFycmllcnM/',
            b'VGhpcyBtYW4gaGFkIGtlcHQgYSBzY2hvb2w=',
            b'QW5kIHJvZGUgb3VyIHdpbmdlZCBob3JzZS4=',
            b'VGhpcyBvdGhlciBoaXMgaGVscGVyIGFuZCBmcmllbmQ=',
            b'V2FzIGNvbWluZyBpbnRvIGhpcyBmb3JjZTs=',
            b'SGUgbWlnaHQgaGF2ZSB3b24gZmFtZSBpbiB0aGUgZW5kLA==',
            b'U28gc2Vuc2l0aXZlIGhpcyBuYXR1cmUgc2VlbWVkLA==',
            b'U28gZGFyaW5nIGFuZCBzd2VldCBoaXMgdGhvdWdodC4=',
            b'VGhpcyBvdGhlciBtYW4gSSBoYWQgZHJlYW1lZA==',
            b'QSBkcnVua2VuLCB2YWluLWdsb3Jpb3VzIGxvdXQu',
            b'SGUgaGFkIGRvbmUgbW9zdCBiaXR0ZXIgd3Jvbmc=',
            b'VG8gc29tZSB3aG8gYXJlIG5lYXIgbXkgaGVhcnQs',
            b'WWV0IEkgbnVtYmVyIGhpbSBpbiB0aGUgc29uZzs=',
            b'SGUsIHRvbywgaGFzIHJlc2lnbmVkIGhpcyBwYXJ0',
            b'SW4gdGhlIGNhc3VhbCBjb21lZHk7',
            b'SGUsIHRvbywgaGFzIGJlZW4gY2hhbmdlZCBpbiBoaXMgdHVybiw=',
            b'VHJhbnNmb3JtZWQgdXR0ZXJseTo=',
            b'QSB0ZXJyaWJsZSBiZWF1dHkgaXMgYm9ybi4=',
        ]
        ciphertexts = []
        for plaintext in plaintexts:
            ciphertexts.append(enc_CTR(from_b64(plaintext), b'\x01' * 16))
        ciphertexts.sort()

        guess = xor(b'th', b'\xe2\xc6') + xor(b'e', b'\xca')
        print('Guess: %s' % guess)
        for ciphertext in ciphertexts:
            print(xor(ciphertext, guess, repeat=False))

    def test_challenge20(self):
        with open("../../C/tests/20.txt", 'rb') as f:
            lines = f.read().split(b'\n')
        ciphertexts = []
        for line in lines:
            ciphertexts.append(enc_CTR(from_b64(line), b'YELLOW SUBMARINE'))

        keystream = b''
        for i in range(len(ciphertexts[0])):
            buffer = b''
            for ciphertext in ciphertexts:
                if i < len(ciphertext):
                    buffer += bytes([ciphertext[i]])
            keystream += crack_xor(buffer)
            print(xor(keystream, ciphertexts[0]))

        print(keystream)
        for ciphertext in ciphertexts:
            print(xor(ciphertext, keystream))

    def test_challenge21(self):
        # now = int(datetime.now().timestamp())
        # self.assertEqual(MT19937(now).genrand_int32(), MT19937(now).genrand_int32())
        # self.assertNotEqual(MT19937(now).genrand_int32(), MT19937(now + 1).genrand_int32())
        mt19937_c_1234567890 = [
            2657703298, 1462474751, 2541004134, 640082991, 3816866956,
            998313779, 3829628193, 1854614443, 1965237353, 3628085564,
            3342292366, 728520329, 1147030148, 767688236, 4278243616,
            40036090, 2319689913, 405604390, 2308637732, 889309503,
            1722279212, 3455024912, 3029694783, 3377489879, 1740258867,
            1460526363, 4080179173, 3374255553, 132086902, 1408914639,
            584222700, 2649164206, 356384632, 124179667, 1819014197,
            1481381825, 1007157946, 1940179051, 3210209959, 3861000209,
            2799367980, 1146380362, 2963470829, 4148304223, 704950970,
            1809127528, 3764200138, 3175596897, 1921281233, 987174450,
            2485544997, 885670600, 2249610877, 2500129383, 2692474462,
            2462568875, 1497630491, 3039436152, 1125700123, 1435487641,
            322039037, 2039021416, 770541610, 3287593442, 3564798172,
            3370865819, 4241702065, 2650072529, 486452264, 704129540,
            2742182638, 2112526287, 3137761114, 2076998165, 3793363367,
            3431682810, 2264349882, 1781218076, 2855623794, 2594604725,
            3187265510, 4181199635, 4040870452, 502811715, 3011765420,
            2320408153, 1268490804, 4145478184, 3269946213, 4156281697,
            3332631785, 3673010362, 1588515731, 725051023, 3844814649,
            3413184343, 1420895978, 3121895872, 3698345822, 2518763166
        ]
        rando = MT19937(s=1234567890)
        for known in mt19937_c_1234567890:
            self.assertEqual(known, rando.genrand_int32())

    def test_challenge22(self):
        past = datetime.now() - timedelta(seconds=random.randint(0, 10000))
        past_rand_data = MT19937(int(past.timestamp())).genrand_int32()

        for i in range(0, 20000):
            test_time = datetime.now() - timedelta(seconds=i)
            test_rand_data = MT19937(int(test_time.timestamp())).genrand_int32()
            if test_rand_data == past_rand_data:
                self.assertEqual(past, test_time)
                return
        self.assertTrue(False)
