# tests for phase 2 (ChaCha20-Poly1305).
# the block function and poly1305 are checked against the official RFC 8439
# vectors. encrypt and aead are checked with a round-trip on a sample message M.

from primitives.chacha20 import chacha20_block, chacha20
from primitives.poly1305 import poly1305_mac
from primitives.aead import encrypt, decrypt

# a sample message to encrypt and decrypt (just some filler paragraph text)
M = (
    "Lorem ipsum dolor sit amet, consectetur adipiscing elit, sed do eiusmod "
    "tempor incididunt ut labore et dolore magna aliqua. Ut enim ad minim veniam, "
    "quis nostrud exercitation ullamco laboris nisi ut aliquip ex ea commodo consequat. "
    "Duis aute irure dolor in reprehenderit in voluptate velit esse cillum dolore eu "
    "fugiat nulla pariatur. Excepteur sint occaecat cupidatat non proident, sunt in "
    "culpa qui officia deserunt mollit anim id est laborum."
)


def test_chacha20_block():
    # RFC 8439 section 2.3.2
    key = bytes(range(32))# 00 01 02 ... 1f
    nonce = bytes.fromhex("000000090000004a00000000")
    block = chacha20_block(key, 1, nonce)
    assert block.hex() == (
        "10f1e7e4d13b5915500fdd1fa32071c4"
        "c7d1f4c733c068030422aa9ac3d46c4e"
        "d2826446079faa0914c2d705d98b02a2"
        "b5129cd1de164eb9cbd083e8a2503c4e"
    )


def test_chacha20_encrypt():
    # encrypt M then decrypt it again, we should get M back
    key = bytes(range(32))
    nonce = bytes.fromhex("000000000000004a00000000")
    ciphertext = chacha20(key, 1, nonce, M.encode())
    assert ciphertext != M.encode()# the data actually changed
    assert chacha20(key, 1, nonce, ciphertext) == M.encode()


def test_poly1305():
    # RFC 8439 section 2.5.2
    key = bytes.fromhex("85d6be7857556d337f4452fe42d506a8"
                        "0103808afb0db2fd4abff6af4149f51b")
    message = "Cryptographic Forum Research Group"
    assert poly1305_mac(key, message.encode()).hex() == "a8061dc1305136c6c22b8baf0c0127a9"


def test_aead():
    # encrypt M with some associated data, then check it round-trips and that
    # tampering is caught
    key = bytes.fromhex("808182838485868788898a8b8c8d8e8f"
                        "909192939495969798999a9b9c9d9e9f")
    nonce = bytes.fromhex("070000004041424344454647")
    aad = bytes.fromhex("50515253c0c1c2c3c4c5c6c7")

    out = encrypt(key, nonce, aad, M.encode())
    # decrypting should give back the original message
    assert decrypt(key, nonce, aad, out) == M.encode()

    # flipping one byte must make decryption fail
    tampered = bytearray(out)
    tampered[0] ^= 1
    try:
        decrypt(key, nonce, aad, bytes(tampered))
        assert False, "tampered message should not decrypt"
    except ValueError:
        pass


if __name__ == "__main__":
    test_chacha20_block()
    test_chacha20_encrypt()
    test_poly1305()
    test_aead()
    print("pass")
