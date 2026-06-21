# SHA-256 hash function, written from scratch (no crypto libraries).
# Follows the FIPS 180-4 standard.

# These two constant tables come straight from the SHA-256 standard.
# K holds the 64 round constants.
K = (
    0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
    0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3, 0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
    0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc, 0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
    0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7, 0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
    0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13, 0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
    0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
    0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
    0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208, 0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2,
)#cubic roots of 2, 3, 5, 311 and then remove the integer part (keep fractional)

# The 8 starting values for the hash.
INITIAL_HASH = (0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a,
                0x510e527f, 0x9b05688c, 0x1f83d9ab, 0x5be0cd19)#sqr (prime) roots of 2, 3, 5, 7, 11, 13, 17, 19

MASK32 = 0xffffffff# keeps numbers at 32 bits (Python ints are unlimited otherwise)


def rotate_right(x, n):
    # rotate a 32-bit number to the right by n bits
    return ((x >> n) | (x << (32 - n))) & MASK32


def sha256(message):
    # copy the starting values, we update these as we go
    h = list(INITIAL_HASH)

    # padding: the message has to be a multiple of 64 bytes. add one 0x80 byte,
    # then zeros, then the original length (in bits) as an 8-byte number at the end.
    original_bit_length = (len(message) * 8) & 0xffffffffffffffff
    message = message + b"\x80"
    zeros = (56 - len(message)) % 64# add zeros until the length is 56 mod 64
    message = message + bytes(zeros)
    message = message + original_bit_length.to_bytes(8, "big")

    # process the message 64 bytes (one block) at a time
    for start in range(0, len(message), 64):
        block = message[start:start + 64]

        # build the "message schedule": 64 words of 32 bits each.
        # first 16 come from the block, the rest are calculated from those.
        w = [int.from_bytes(block[i:i + 4], "big") for i in range(0, 64, 4)] + [0] * 48
        for i in range(16, 64):
            s0 = rotate_right(w[i - 15], 7) ^ rotate_right(w[i - 15], 18) ^ (w[i - 15] >> 3)
            s1 = rotate_right(w[i - 2], 17) ^ rotate_right(w[i - 2], 19) ^ (w[i - 2] >> 10)
            w[i] = (w[i - 16] + s0 + w[i - 7] + s1) & MASK32

        # working variables, start them from the current hash
        a, b, c, d, e, f, g, hh = h

        # main loop, 64 rounds of mixing
        for i in range(64):
            S1 = rotate_right(e, 6) ^ rotate_right(e, 11) ^ rotate_right(e, 25)
            choose = (e & f) ^ ((~e & MASK32) & g)# picks bits from f or g based on e
            temp1 = (hh + S1 + choose + K[i] + w[i]) & MASK32
            S0 = rotate_right(a, 2) ^ rotate_right(a, 13) ^ rotate_right(a, 22)
            majority = (a & b) ^ (a & c) ^ (b & c)# the bit most of a, b, c agree on
            temp2 = (S0 + majority) & MASK32

            # shift everything down by one slot and add the new values in
            hh = g
            g = f
            f = e
            e = (d + temp1) & MASK32
            d = c
            c = b
            b = a
            a = (temp1 + temp2) & MASK32

        # add the working variables back into the running hash
        h[0] = (h[0] + a) & MASK32
        h[1] = (h[1] + b) & MASK32
        h[2] = (h[2] + c) & MASK32
        h[3] = (h[3] + d) & MASK32
        h[4] = (h[4] + e) & MASK32
        h[5] = (h[5] + f) & MASK32
        h[6] = (h[6] + g) & MASK32
        h[7] = (h[7] + hh) & MASK32

    # turn the 8 final numbers into 32 bytes and return them
    return b"".join(x.to_bytes(4, "big") for x in h)
