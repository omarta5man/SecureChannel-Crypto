# Poly1305 one-time message authentication code. Follows RFC 8439.
# It takes a one time 32byte key and a message, and produces a 16-byte tag


# the prime number that all the math is done modulo: 2^130 - 5
P = (1 << 130) - 5


def poly1305_mac(key, message):
    # split the 32-byte key into two halves: r (first 16) and s (last 16)
    r = int.from_bytes(key[0:16], "little")
    s = int.from_bytes(key[16:32], "little")

    #clear some specific bits of r
    r = r & 0x0ffffffc0ffffffc0ffffffc0fffffff

    accumulator = 0
    # process the message 16 bytes at a time
    for offset in range(0, len(message), 16):
        block = message[offset:offset + 16]
        #read the block as a little endian number, then set a 1 bit just above it
        n = int.from_bytes(block, "little") + (1 << (8 * len(block)))
        accumulator = (accumulator + n) % P
        accumulator = (accumulator * r) % P

    # add s and keep the low 128 bits as the tag
    accumulator = (accumulator + s) % (1 << 128)
    return accumulator.to_bytes(16, "little")
