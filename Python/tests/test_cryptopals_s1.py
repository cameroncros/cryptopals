import unittest

from libhannah.basics import to_b64, from_hex, from_b64, to_hex
from libhannah.ssl import dec_ECB, enc_ECB, detect_ECB
from libhannah.tools import is_english, hamming_distance
from libhannah.xor import xor


def crack_xor(buffer: bytes) -> bytes:
    lowest_score = 999
    best_key = None
    for i in range(255):
        key = bytes([i])
        result = xor(buffer, key)
        score = is_english(result)
        # print("%i)[%f]: %s" % (i, score, result))
        if score < lowest_score:
            best_key = key
            lowest_score = score
    return best_key


class CryptoPalsS1(unittest.TestCase):
    def test_challenge1(self):
        """
        Convert hex to base64 and back.
        """
        self.assertEqual(b'SSdtIGtpbGxpbmcgeW91ciBicmFpbiBsaWtlIGEgcG9pc29ub3VzIG11c2hyb29t',
                         to_b64(from_hex(
                             b'49276d206b696c6c696e6720796f757220627261696e206c696b65206120706f69736f6e6f7573206d757368726f6f6d')))
        self.assertEqual(
            b'49276d206b696c6c696e6720796f757220627261696e206c696b65206120706f69736f6e6f7573206d757368726f6f6d',
            to_hex(from_b64(
                b'SSdtIGtpbGxpbmcgeW91ciBicmFpbiBsaWtlIGEgcG9pc29ub3VzIG11c2hyb29t')))

    def test_challenge2(self):
        """
        XOR two byte arrays
        """
        self.assertEqual(b'746865206b696420646f6e277420706c6179',
                         to_hex(xor(from_hex(b'1c0111001f010100061a024b53535009181c'),
                                    from_hex(b'686974207468652062756c6c277320657965'))))
        self.assertEqual(b'\x01\x00\x00\x04', xor(b'\x01\x02\x03\x04', b'\x02\x03', repeat=False, offset=1))

    def test_challenge3(self):
        """
        Defeat single byte XOR
        """
        buffer = from_hex(b'1b37373331363f78151b7f2b783431333d78397828372d363c78373e783a393b3736')
        best_key = crack_xor(buffer)

        self.assertEqual(b"Cooking MC's like a pound of bacon",
                         xor(buffer, best_key))
        self.assertEqual(bytes([88]), best_key)

    def test_challenge4(self):
        """
        Detect XOR'd string
        """
        with open("../../C/tests/4.txt", 'rb') as f:
            lines = f.read().split(b'\n')
            for line in lines:
                data = from_hex(line)
                for i in range(255):
                    result = xor(data,
                                 bytes([i]))
                    if is_english(result) < 0.75:
                        print("Line: %s" % line)
                        print("Result: %s" % result)

                        self.assertEqual(b"Now that the party is jumping\n", result)
                        self.assertEqual(53, i)
                        return
        self.assertFalse(True)  # Should not happen

    def test_challenge5(self):
        """
        Repeating key XOR
        """
        self.assertEqual(
            b"0b3637272a2b2e63622c2e69692a23693a2a3c6324202d623d63343c2a2622632427276527"
            b"2a282b2f20430a652e2c652a3124333a653e2b2027630c692b20283165286326302e27282f",
            to_hex(xor(b"Burning 'em, if you ain't quick and nimble\n"
                       b"I go crazy when I hear a cymbal",
                       b"ICE")))

    def test_challenge6a(self):
        """
        Get hamming distance
        """
        self.assertEqual(37, hamming_distance(b'this is a test',
                                              b'wokka wokka!!!'))

    def test_challenge6b(self):
        """
        Detect key length of XOR'd ciphertext
        """
        with open("../../C/tests/6.txt", 'rb') as f:
            encrypted = from_b64(f.read())

        min_distance = 999
        min_index = 0
        for i in range(1, 64):
            distance = 0
            for j in range(10):
                distance += hamming_distance(encrypted[j * i: (j + 1) * i],
                                             encrypted[(j + 1) * i: (j + 2) * i])
            distance /= 10
            distance /= i * 8
            print("%i) %f" % (i, distance))
            if distance < min_distance:
                min_index = i
                min_distance = distance

        self.assertEqual(29, min_index)

    def test_challenge6c(self):
        """
        Detect key length of XOR'd ciphertext
        """
        with open("../../C/tests/6.txt", 'rb') as f:
            encrypted = from_b64(f.read())

        key_length = 29
        cipher_key = b''
        for key in range(key_length):
            block = b''
            i = 0
            while i < len(encrypted):
                block += encrypted[i + key:i + key + 1]
                i += key_length

            cipher_key += crack_xor(block)
        self.assertEqual(key_length, len(cipher_key))
        self.assertEqual(b'Terminator X: Bring the noise', cipher_key)

    def test_challenge7(self):
        """
        ECB decrypt/encrypt
        """
        with open("../../C/tests/7.txt", 'rb') as f:
            encrypted = from_b64(f.read())
        decrypted = dec_ECB(encrypted, b'YELLOW SUBMARINE')

        self.assertTrue(decrypted.decode('UTF-8').startswith("I'm back and I'm ringin' the bell"))
        self.assertTrue(decrypted.decode('UTF-8').endswith("Play that funky music \n"))

        recrypted = enc_ECB(decrypted, b'YELLOW SUBMARINE')
        self.assertEqual(encrypted, recrypted)

    def test_challenge8(self):
        """
        Detect ECB
        """
        with open("../../C/tests/8.txt", 'rb') as f:
            lines = f.read().split(b'\n')
        found_lines = []
        for line in lines:
            encrypted = from_hex(line)
            if detect_ECB(encrypted):
                found_lines.append(line)
        self.assertEqual(1, len(found_lines))
        self.assertEqual(b'd880619740a8a19b7840a8a31c810a3d'
                         b'08649af70dc06f4fd5d2d69c744cd283'
                         b'e2dd052f6b641dbf9d11b0348542bb57'
                         b'08649af70dc06f4fd5d2d69c744cd283'
                         b'9475c9dfdbc1d46597949d9c7e82bf5a'
                         b'08649af70dc06f4fd5d2d69c744cd283'
                         b'97a93eab8d6aecd566489154789a6b03'
                         b'08649af70dc06f4fd5d2d69c744cd283'
                         b'd403180c98c8f6db1f2a3f9c4040deb0'
                         b'ab51b29933f2c123c58386b06fba186a', found_lines[0])
