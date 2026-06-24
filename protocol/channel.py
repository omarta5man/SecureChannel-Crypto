"""the secure channel used when handshake is complete
every message is encrypted with ChaCha20-Poly1305 (AEAD), a header (var,
sender, counter), and the counter is used to detect replays and out of order messages
"""
from primitives.aead import encrypt, decrypt

VAR = b"SC1"# protocol version tag


def new_session(keys, role):
    # each side sends with one key and receives with the other so the two never share a key
    if role == "client":
        session = {
            "send_key": keys["client_to_server_key"],
            "send_iv": keys["client_to_server_iv"],
            "recv_key": keys["server_to_client_key"],
            "recv_iv": keys["server_to_client_iv"],
            "sender_id": 0,
        }
    else:
        session = {
            "send_key": keys["server_to_client_key"],
            "send_iv": keys["server_to_client_iv"],
            "recv_key": keys["client_to_server_key"],
            "recv_iv": keys["client_to_server_iv"],
            "sender_id": 1,
        }
    session["send_counter"] = 0
    session["last_seen"] = -1#last highest counter accepted
    return session


def nonce_func(base_iv, counter):
    #nonce = iv XOR counter, counter always increments so nonce is never the same during a session, which ChaCha20 needs
    counter_bytes = bytes(4) + counter.to_bytes(8, "big")
    return bytes(a ^ b for a, b in zip(base_iv, counter_bytes))


def seal(session, plaintext):
    counter = session["send_counter"]
    #header: 3byte var + 1byte sender id + 8byte counter = 12 bytes
    header = VAR + bytes([session["sender_id"]]) + counter.to_bytes(8, "big")
    nonce = nonce_func(session["send_iv"], counter)
    ciphertext = encrypt(session["send_key"], nonce, header, plaintext)
    session["send_counter"] += 1
    return header + ciphertext


def unseal(session, message):
    header = message[:12]
    ciphertext = message[12:]
    counter = int.from_bytes(header[4:12], "big")

    # reject anything we already seen or that arrives out of order
    if counter <= session["last_seen"]:
        raise ValueError("replay: counter %d was already seen" % counter)

    nonce = nonce_func(session["recv_iv"], counter)
    #decrypt raises ValueError if the header or ciphertext was tampered with
    plaintext = decrypt(session["recv_key"], nonce, header, ciphertext)

    session["last_seen"] = counter
    return plaintext
