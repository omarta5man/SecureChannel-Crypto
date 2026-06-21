# HKDF key derivation, built on HMAC-SHA256. Follows RFC 5869.
# Two steps: "extract" squeezes the input into one fixed-size key,
# "expand" stretches that key into as many bytes as we ask for.

from primitives.hmac import hmac_sha256

HASH_LEN = 32  # SHA-256 output size in bytes


def hkdf_extract(salt, input_key_material):
    # if no salt is given, the spec says to use a string of zero bytes
    if not salt:
        salt = bytes(HASH_LEN)
    # the extract step is just one HMAC
    return hmac_sha256(salt, input_key_material)


def hkdf_expand(prk, info, length):
    if length > 255 * HASH_LEN:
        raise ValueError("HKDF can't output that many bytes")

    output = b""
    block = b""
    counter = 1
    # keep making blocks and chaining them together until we have enough bytes
    while len(output) < length:
        block = hmac_sha256(prk, block + info + bytes([counter]))
        output = output + block
        counter = counter + 1
    return output[:length]


def hkdf(salt, input_key_material, info, length):
    # shortcut to run both steps in one call
    prk = hkdf_extract(salt, input_key_material)
    return hkdf_expand(prk, info, length)
