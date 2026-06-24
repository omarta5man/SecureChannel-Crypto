# turns the handshake's shared secret into the actual keys used for messaging.
# the pre-shared key (PSK) is mixed in as the HKDF salt, so both the key
# exchange AND the shared password are needed to get the right keys.

from primitives.hkdf import hkdf_extract, hkdf_expand


def derive_session_keys(psk, shared_secret):
    # prk = extracting psk and shared secret using hkdf
    prk = hkdf_extract(psk, shared_secret)

    #expanding the prk to get the keys and ivs for the channel (client to server and server to client)
    return {
        "client_to_server_key": hkdf_expand(prk, b"securechannel client to server key", 32),
        "server_to_client_key": hkdf_expand(prk, b"securechannel server to client key", 32),
        "client_to_server_iv":  hkdf_expand(prk, b"securechannel client to server iv", 12),
        "server_to_client_iv":  hkdf_expand(prk, b"securechannel server to client iv", 12),
    }
