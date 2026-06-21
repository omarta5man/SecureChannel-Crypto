# Tests for phase 1. The expected answers come from the official standards:
# SHA-256 from FIPS 180-4, HMAC from RFC 4231, HKDF from RFC 5869.

from primitives.sha256 import sha256
from primitives.hmac import hmac_sha256
from primitives.hkdf import hkdf_extract, hkdf_expand


def test_sha256():
    # "abc" classic example
    assert sha256(b"abc").hex() == \
        "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"
    # empty input is another known answer
    assert sha256(b"").hex() == \
        "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
    #known example also
    assert sha256(b"abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq").hex() == \
        "248d6a61d20638b8e5c026930c3e6039a33ce45964ff2167f6ecedd419db06c1"


def test_hmac():
    # test case 1 from RFC 4231
    key = b"\x0b" * 20
    message = b"Hi There"
    assert hmac_sha256(key, message).hex() == \
        "b0344c61d8db38535ca8afceaf0bf12b881dc200c9833da726e9376c2e32cff7"


def test_hkdf():
    # test case 1 from RFC 5869
    ikm = b"\x0b" * 22
    salt = bytes(range(0x00, 0x0d))
    info = bytes(range(0xf0, 0xfa))
    prk = hkdf_extract(salt, ikm)
    assert prk.hex() == \
        "077709362c2e32df0ddc3f0dc47bba6390b6c73bb50f9c3122ec844ad7c2b3e5"
    okm = hkdf_expand(prk, info, 42)
    assert okm.hex() == \
        "3cb25f25faacd57a90434f64d0362f2a2d2d0a90cf1a5a4c5db02d56ecc4c5bf34007208d5b887185865"


if __name__ == "__main__":
    test_sha256()
    test_hmac()
    test_hkdf()
    print("pass")
