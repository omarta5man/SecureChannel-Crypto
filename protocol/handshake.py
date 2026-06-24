"""the handshake. two sides agree on a shared secret with X25519, prove they both
# know the pre-shared key by swapping HMAC tags over the handshake transcript,
# and end up with a ready-to-use session."""

#messages:
#M1 client to server: version, client id, client public key
#M2 server to client: version, server id, server public key, server tag
#M3 client to server: client tag

from primitives.x25519 import generate_keypair, x25519
from primitives.hmac import hmac_sha256
from protocol.messages import send_message, recv_message
from protocol.transcript import build_transcript
from protocol.keyschedule import derive_session_keys
from protocol.channel import new_session

VAR = b"SC1"# protocol version tag


def run_client(sock, psk, my_id):
    priv, pub = generate_keypair()
    send_message(sock, [VAR, my_id, pub])#M1

    # the incoming version field is not needed, both sides use VAR
    unused, server_id, server_pub, server_tag = recv_message(sock)#M2

    shared = x25519(priv, server_pub)
    transcript = build_transcript(VAR, my_id, server_id, pub, server_pub)

    # check if server really knows the psk (not tampered with)
    if server_tag != hmac_sha256(psk, transcript + b"server"):
        raise ValueError("handshake failed: server tag did not match")

    keys = derive_session_keys(psk, shared)
    send_message(sock, [hmac_sha256(psk, transcript + b"client")])#M3
    session = new_session(keys, "client")
    session["peer"] = server_id# remember the other side's name for the chat
    return session


def run_server(sock, psk, my_id):
    unused, client_id, client_pub = recv_message(sock)# M1

    priv, pub = generate_keypair()
    shared = x25519(priv, client_pub)
    transcript = build_transcript(VAR, client_id, my_id, client_pub, pub)

    server_tag = hmac_sha256(psk, transcript + b"server")
    send_message(sock, [VAR, my_id, pub, server_tag])#M2

    client_tag = recv_message(sock)[0]# M3
    if client_tag != hmac_sha256(psk, transcript + b"client"):
        raise ValueError("handshake failed: client tag did not match")

    keys = derive_session_keys(psk, shared)
    session = new_session(keys, "server")
    session["peer"] = client_id# remember the other side's name for the chat
    return session
