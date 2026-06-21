#ChaCha20 stream cipher. Follows RFC 8439.
#It turns a key + nonce + counter into a random stream bytes
# To encrypt we XOR the message with that stream, to decrypt we XOR again

MASK32 = 0xffffffff

# The four fixed words at the start of the state (ASCII)
CONSTANTS = (0x61707865, 0x3320646e, 0x79622d32, 0x6b206574)


def rotate_left(x, n):
    # shift arth a 32-bit number to the left by n bits
    return ((x << n) | (x >> (32 - n))) & MASK32


def quarter_round(state, a, b, c, d):
    # the core mixing step. it works on four words of the state, given by index.
    state[a] = (state[a] + state[b]) & MASK32
    state[d] = rotate_left(state[d] ^ state[a], 16)
    state[c] = (state[c] + state[d]) & MASK32
    state[b] = rotate_left(state[b] ^ state[c], 12)
    state[a] = (state[a] + state[b]) & MASK32
    state[d] = rotate_left(state[d] ^ state[a], 8)
    state[c] = (state[c] + state[d]) & MASK32
    state[b] = rotate_left(state[b] ^ state[c], 7)


def chacha20_block(key, counter, nonce):
    # build the 16-word starting state:
    # 4 constant words, 8 key words, 1 counter word, 3 nonce words
    state = list(CONSTANTS)
    state += [int.from_bytes(key[i:i + 4], "little") for i in range(0, 32, 4)]# 32-byte key -> 8 words
    state.append(counter & MASK32)# block counter
    state += [int.from_bytes(nonce[i:i + 4], "little") for i in range(0, 12, 4)]# 12-byte nonce -> 3 words

    # work on a copy so we can add the original back at the end
    working = list(state)

    #20 rounds = 10 times of (4 column rounds + 4 diagonal rounds)
    for _ in range(10):
        # column rounds
        quarter_round(working, 0, 4, 8, 12)
        quarter_round(working, 1, 5, 9, 13)
        quarter_round(working, 2, 6, 10, 14)
        quarter_round(working, 3, 7, 11, 15)
        # diagonal rounds
        quarter_round(working, 0, 5, 10, 15)
        quarter_round(working, 1, 6, 11, 12)
        quarter_round(working, 2, 7, 8, 13)
        quarter_round(working, 3, 4, 9, 14)

    # add the mixed state back into the original state
    out = [(working[i] + state[i]) & MASK32 for i in range(16)]

    # turn the 16 words into 64 bytes (little-endian)
    return b"".join(x.to_bytes(4, "little") for x in out)


def chacha20(key, counter, nonce, data):
    # encrypt or decrypt by XORing the data with the keystream, 64 bytes at a time
    result = bytearray()
    for offset in range(0, len(data), 64):
        block = data[offset:offset + 64]
        keystream = chacha20_block(key, counter + offset // 64, nonce)
        for i in range(len(block)):
            result.append(block[i] ^ keystream[i])
    return bytes(result)
