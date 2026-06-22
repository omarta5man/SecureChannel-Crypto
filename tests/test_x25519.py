# Test X25519
#known variables from RFC 7748 amd some generated ones

from primitives.x25519 import x25519, generate_keypair, base


def test_single_vectors():
    scalar = (0xa546e36bf0527c9d3b16154b82465edd62144c0ac1fc5a18506a2244ba449ac4).to_bytes(32, "big")
    u = (0xe6db6867583030db3594c1a424b15f7c726624ec26b3353b10a903a6d0ab1c4c).to_bytes(32, "big")
    expected = (0xc3da55379de9c6908e94ea4df28d084f32eccf03491c71f754b4075577a28552).to_bytes(32, "big")
    assert x25519(scalar, u) == expected

    scalar = (0x4b66e9d4d1b4673c5ad22691957d6af5c11b6421e0ea01d42ca4169e7918ba0d).to_bytes(32, "big")
    u = (0xe5210f12786811d3f4b7959d0538ae2c31dbe7106fc03c3efc4cd549c715a493).to_bytes(32, "big")
    expected = (0x95cbde9476e8907d7aade45cb4b873f88b595a68799fa152e6f8f7647aac7957).to_bytes(32, "big")
    assert x25519(scalar, u) == expected


def test_diffie_hellman():
    P1_priv = (0x77076d0a7318a57d3c16c17251b26645df4c2f87ebc0992ab177fba51db92c2a).to_bytes(32, "big")
    P2_priv = (0x5dab087e624a8a4b79e17f8b83800ee66f3bb1292618b6fd1c2f8b27ff88e0eb).to_bytes(32, "big")

    P1_pub = x25519(P1_priv, base)
    P2_pub = x25519(P2_priv, base)
    assert P1_pub == (0x8520f0098930a754748b7ddcb43ef75a0dbf3a0d26381af4eba4a98eaa9b4e6a).to_bytes(32, "big")
    assert P2_pub == (0xde9edb7d7b7dc1b4d35b61c2ece435373f8343c85b78674dadfc7e146f882b4f).to_bytes(32, "big")

    # both sides must arrive at the same shared secret
    P1_shared = x25519(P1_priv, P2_pub)
    P2_shared = x25519(P2_priv, P1_pub)
    assert P1_shared == P2_shared
    assert P1_shared == (0x4a5d9d5ba4ce2de1728e3bf480350f25e07e21c947d19e3376f09b3c1e161742).to_bytes(32, "big")


def test_iteration():
    k = base
    u = k
    for i in range(1000):
        k, u = x25519(k, u), k
        if i == 0:
            assert k == (0x422c8e7a6227d7bca1350b3e2bb7279f7897b87bb6854b783c60e80311ae3079).to_bytes(32, "big")
    assert k == (0x684cf59ba83309552800ef566f2f4d3c1c3887c49360e3875f2eb94d99532c51).to_bytes(32, "big")


def test_keypair_roundtrip():
    # two generated keypairs should agree on a shared secret
    a_priv, a_pub = generate_keypair()
    b_priv, b_pub = generate_keypair()
    assert x25519(a_priv, b_pub) == x25519(b_priv, a_pub)


if __name__ == "__main__":
    test_single_vectors()
    test_diffie_hellman()
    test_iteration()
    test_keypair_roundtrip()
    print("pass")
