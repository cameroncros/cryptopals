import random

from Crypto.Cipher import AES

from cryptolib.xor import xor

AES_BLOCK_SIZE = 16


def pkcs7_pad(buffer: bytes, block_size=AES_BLOCK_SIZE) -> bytes:
    padding = block_size - len(buffer) % block_size
    return buffer + (bytes([padding]) * padding)


def pkcs7_unpad(buffer: bytes) -> bytes:
    padding = buffer[-1]
    for char in buffer[len(buffer) - padding: len(buffer)]:
        if char != padding:
            padding = 0
    return buffer[0: len(buffer) - padding]

def pkcs7_validate(buffer: bytes) -> bool:
    padding = buffer[-1]
    for char in buffer[len(buffer) - padding: len(buffer)]:
        if char != padding:
            return False
    return True

def enc_ECB(buffer: bytes, key: bytes) -> bytes:
    assert (len(key) == AES_BLOCK_SIZE)
    cipher = AES.new(key, AES.MODE_ECB)
    result = b''
    i = 0
    padded = pkcs7_pad(buffer)
    for i in range(0, len(padded), AES_BLOCK_SIZE):
        end = min(i + AES_BLOCK_SIZE, len(padded))
        next_chunk = padded[i:end]
        result += cipher.encrypt(next_chunk)
    return pkcs7_unpad(result)


def dec_ECB(buffer: bytes, key: bytes) -> bytes:
    assert (len(key) == AES_BLOCK_SIZE)
    cipher = AES.new(key, AES.MODE_ECB)
    result = b''
    i = 0
    for i in range(0, len(buffer), AES_BLOCK_SIZE):
        end = min(i + AES_BLOCK_SIZE, len(buffer))
        next_chunk = buffer[i:end]
        result += cipher.decrypt(next_chunk)
    return pkcs7_unpad(result)


def detect_ECB(buffer: bytes) -> bool:
    for i in range(0, len(buffer), AES_BLOCK_SIZE):
        first_block = buffer[i:i + AES_BLOCK_SIZE]
        for j in range(i + AES_BLOCK_SIZE, len(buffer), AES_BLOCK_SIZE):
            second_block = buffer[j:j + AES_BLOCK_SIZE]
            if first_block == second_block:
                return True
    return False


def enc_CBC(buffer: bytes, key: bytes, iv: bytes) -> bytes:
    assert (len(key) == AES_BLOCK_SIZE)
    assert (len(iv) == AES_BLOCK_SIZE)
    padded = pkcs7_pad(buffer)
    cipher = AES.new(key, AES.MODE_ECB)
    result = b''
    last_chunk = iv
    for i in range(0, len(padded), AES_BLOCK_SIZE):
        end = min(i + AES_BLOCK_SIZE, len(padded))
        chunk = padded[i:end]
        last_chunk = cipher.encrypt(xor(chunk, last_chunk))
        result += last_chunk
    return result


def dec_CBC(buffer: bytes, key: bytes, iv: bytes) -> bytes:
    assert (len(key) == AES_BLOCK_SIZE)
    assert (len(iv) == AES_BLOCK_SIZE)

    cipher = AES.new(key, AES.MODE_ECB)
    result = b''
    last_chunk = iv
    for i in range(0, len(buffer), AES_BLOCK_SIZE):
        end = min(i + AES_BLOCK_SIZE, len(buffer))
        chunk = buffer[i:end]
        result += xor(cipher.decrypt(chunk), last_chunk)
        last_chunk = chunk
    return pkcs7_unpad(result)
