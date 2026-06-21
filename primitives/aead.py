#ChaCha20-Poly1305 authenticated encryption (AEAD).RFC 8439.
# It uses ChaCha20 to encrypt the message and Poly1305 to make an authentication tag.

from primitives.chacha20 import chacha20, chacha20_block
from primitives.poly1305 import poly1305_mac


def poly1305_key_gen(key, nonce):
    # make a one-time Poly1305 key from the ChaCha20 keystream at counter 0
    block = chacha20_block(key, 0, nonce)
    return block[0:32]


def pad16(data):
    #return the zero bytes needed to round the length up to a multiple of 16
    if len(data) % 16 == 0:
        return b""
    return bytes(16 - len(data) % 16)


def build_mac_data(aad, ciphertext):
    #aad (padded) + ciphertext (padded) + length of aad + length of ciphertext
    data = aad + pad16(aad) + ciphertext + pad16(ciphertext)
    data += len(aad).to_bytes(8, "little")# 8byte little-endian length
    data += len(ciphertext).to_bytes(8, "little")
    return data


def encrypt(key, nonce, aad, plaintext):
    # one time key for the tag
    otk = poly1305_key_gen(key, nonce)
    # encrypt the message; counter starts at 1 because counter 0 made the otk
    ciphertext = chacha20(key, 1, nonce, plaintext)
    tag = poly1305_mac(otk, build_mac_data(aad, ciphertext))
    return ciphertext + tag


def constant_time_equal(a, b):
    # compare two byte strings
    if len(a) != len(b):
        return False
    result = 0
    for x, y in zip(a, b):
        result |= x ^ y
    return result == 0


def decrypt(key, nonce, aad, ciphertext_and_tag):
    #last 16 bytes are the tag, the rest is the ciphertext
    ciphertext = ciphertext_and_tag[:-16]
    received_tag = ciphertext_and_tag[-16:]

    # recompute the tag
    otk = poly1305_key_gen(key, nonce)
    expected_tag = poly1305_mac(otk, build_mac_data(aad, ciphertext))

    #if the tags dont match, message or aad are corrupted or the key is wrong
    if not constant_time_equal(received_tag, expected_tag):
        raise ValueError("authentication failed: tag mismatch")

    return chacha20(key, 1, nonce, ciphertext)
