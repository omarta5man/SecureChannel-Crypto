# HMAC using SHA-256, written from scratch. Follows RFC 2104.
# The idea: mix the key into the message two different ways and hash twice.

from primitives.sha256 import sha256

BLOCK_SIZE = 64  # SHA-256 works on 64-byte blocks


def hmac_sha256(key, message):
    # if the key is longer than one block, hash it first to make it shorter
    if len(key) > BLOCK_SIZE:
        key = sha256(key)

    # pad the key with zero bytes so it fills exactly one block
    key = key + bytes(BLOCK_SIZE - len(key))

    # two fixed padding values from the standard
    inner_pad = bytes(b ^ 0x36 for b in key)
    outer_pad = bytes(b ^ 0x5c for b in key)

    # hash the inner part, then hash that result together with the outer part
    inner_hash = sha256(inner_pad + message)
    return sha256(outer_pad + inner_hash)
