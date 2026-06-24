# SecureChannel-Crypto

A secure communication system in Python for Applied Cryptography Course

Two parties establish a shared secret over an insecure network, authenticate each
other, and then exchange messages with confidentiality, integrity, and authenticity
(including support for associated data). Every cryptographic primitive is implemented
from its official specification, no crypto libraries are used inside the
implementation.

## Course

- **Course:** ENCS4320 — Applied Cryptography
- **Institution:** Birzeit University
- **Author:** Omar Takhman (1230002)

## What the program does

A session runs in two phases.

**Phase A — Handshake (key setup and authentication).**

1. **Key exchange.** Each side creates a temporary key pair and they run a
   Diffie–Hellman exchange over the X25519 curve to agree on a shared secret.
2. **Authentication.** Both sides already share a long-term pre-shared key (PSK), agreed
   in person and read from a file. Each side computes `HMAC(PSK, transcript)` over
   the whole handshake (both public keys, both identities, the version) and sends it for
   the other side to check. If the tags don't match, the connection is aborted. This is
   what stops a man-in-the-middle attacker.
3. **Key derivation.** The shared secret is fed into HKDF (with the PSK mixed in
   as the salt) to produce two separate directional keys (client→server and
   server→client) plus the starting nonce material.

**Phase B — Secure messaging.**

1. **Authenticated encryption.** Every message is protected with ChaCha20-Poly1305.
2. **Associated data.** Each message carries a small plaintext header (version, sender id,
   and a message counter). The header is not encrypted but is authenticated, so any
   tampering with it makes decryption fail.
3. **Replay protection.** The counter strictly increases and is tied to the nonce, so
   replayed or reordered messages are detected and rejected.

## Cryptographic primitives

| Component             | Specification | What it gives us                      |
| --------------------- | ------------- | ------------------------------------- |
| SHA-256               | FIPS 180-4    | secure hashing                        |
| HMAC                  | RFC 2104      | message authentication                |
| HKDF                  | RFC 5869      | deriving keys from one shared secret  |
| ChaCha20-Poly1305     | RFC 8439      | authenticated encryption (with AAD)   |
| X25519                | RFC 7748      | Diffie–Hellman key exchange           |

The three foundation primitives build on each other: HMAC is built on SHA-256, and HKDF
is built on HMAC.
