# tests for phase 2 (ChaCha20-Poly1305).
# the block function and poly1305 are checked against the official RFC 8439
# vectors.

from primitives.chacha20 import chacha20_block, chacha20
from primitives.poly1305 import poly1305_mac
from primitives.aead import encrypt, decrypt

# a sample message to encrypt and decrypt (known answer RFC 8439)
M = ("Ladies and Gentlemen of the class of '99: "
    "If I could offer you only one tip for the future, "
    "sunscreen would be it.")


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
    # encrypt M then compare with expected output
    key = bytes(range(32))
    nonce = bytes.fromhex("000000000000004a00000000")
    ciphertext = chacha20(key, 1, nonce, M.encode())
    assert ciphertext.hex() == (
        "6e2e359a2568f98041ba0728dd0d6981"
        "e97e7aec1d4360c20a27afccfd9fae0b"
        "f91b65c5524733ab8f593dabcd62b357"
        "1639d624e65152ab8f530c359f0861d8"
        "07ca0dbf500d6a6156a38e088a22b65e"
        "52bc514d16ccf806818ce91ab7793736"
        "5af90bbf74a35be6b40b8eedf2785e42"
        "874d"
    )


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
    expected = (
        "d31a8d34648e60db7b86afbc53ef7ec2"
        "a4aded51296e08fea9e2b5a736ee62d6"
        "3dbea45e8ca9671282fafb69da92728b"
        "1a71de0a9e060b2905d6a5b67ecd3b36"
        "92ddbd7f2d778b8c9803aee328091b58"
        "fab324e4fad675945585808b4831d7bc"
        "3ff4def08e4b7a9de576d26586cec64b"
        "6116"
        "1ae10b594f09e26a7e902ecbd0600691"#the 16-byte tag is appended last
    )

    out = encrypt(key, nonce, aad, M.encode())
    assert out.hex() == expected
    
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
