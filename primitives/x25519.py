# X25519 Diffie-Hellman key exchange
""" Each side picks a private key and computes a public key. Each side can then
combine its own private key with the other side's public key, and both end
up with the same shared secret.
"""
import os#random bytes for the private key

P = (1 << 255) - 19#the prime number
A24 = 121665#a curve constant, equal to (486662 - 2) / 4
BITS = 255

#the starting point's u-coordinate is 9, written as 32 bytes little endian
base = b"\x09" + bytes(31)


def montgomery_ladder(k, u):
    #walk the bits of k from high to low to multiply the point u by k
    x1 = u
    x2, z2 = 1, 0
    x3, z3 = u, 1
    swap = 0

    for t in range(BITS - 1, -1, -1):
        kt = (k >> t) & 1
        swap ^= kt
        #swap the two points so they follow the current key bit
        if swap:
            x2, x3 = x3, x2
            z2, z3 = z3, z2
        swap = kt

        A = (x2 + z2) % P
        AA = (A * A) % P
        B = (x2 - z2) % P
        BB = (B * B) % P
        E = (AA - BB) % P
        C = (x3 + z3) % P
        D = (x3 - z3) % P
        DA = (D * A) % P
        CB = (C * B) % P
        x3 = ((DA + CB) % P) ** 2 % P
        z3 = (x1 * (((DA - CB) % P) ** 2 % P)) % P
        x2 = (AA * BB) % P
        z2 = (E * ((AA + A24 * E) % P)) % P

    if swap:
        x2, x3 = x3, x2
        z2, z3 = z3, z2

    #the answer is x2/z2, and pow(z2, P-2, P) is the inverse of z2 (Fermat)
    return (x2 * pow(z2, P - 2, P)) % P


def x25519(private, point):
    #clamp the private key so it lands in the safe range (RFC 7748)
    k = bytearray(private)
    k[0] &= 248
    k[31] &= 127
    k[31] |= 64
    k = int.from_bytes(k, "little")

    #the top bit of u is unused, mask it off then reduce mod P
    u = bytearray(point)
    u[31] &= 127
    u = int.from_bytes(u, "little") % P

    return (montgomery_ladder(k, u) % P).to_bytes(32, "little")


def generate_keypair():
    #public key is the base point times the private key
    private = os.urandom(32)
    return private, x25519(private, base)
