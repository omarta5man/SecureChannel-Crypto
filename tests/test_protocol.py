"""tests for the handshake and the secure channel.
we run a real handshake over a socket pair, then check that messaging,
tampering, replay protection and a wrong psk all behave.
"""

import socket
import threading

from protocol.handshake import run_client, run_server
from protocol.channel import seal, unseal


def test_handshake_and_messaging():
    psk = "strong shared password between server/client".encode()
    client_sock, server_sock = socket.socketpair()

    #the server has to run at the same time as the client, so thread is used
    box = []
    def run_the_server():
        box.append(run_server(server_sock, psk, "server".encode()))

    thread = threading.Thread(target=run_the_server)
    thread.start()
    client = run_client(client_sock, psk, "client".encode())
    thread.join()
    server = box[0]

    # messages work in both directions
    from_client = "hi from client"
    from_server = "hi from server"
    assert unseal(server, seal(client, from_client.encode())) == from_client.encode()
    assert unseal(client, seal(server, from_server.encode())) == from_server.encode()

    # changing one byte makes the receiver reject the message
    tampered = bytearray(seal(client, "reject (tampered with message)".encode()))
    tampered[-1] ^= 0x01
    try:
        unseal(server, bytes(tampered))
        assert False, "tampered message should be rejected"
    except ValueError:
        pass

    #sending the same message again is rejected as a replay
    text = "send something else (can't replicate messages)"
    message = seal(client, text.encode())
    assert unseal(server, message) == text.encode()
    try:
        unseal(server, message)
        assert False, "replayed message should be rejected"
    except ValueError:
        pass

    client_sock.close()
    server_sock.close()


def test_wrong_psk():
    client_sock, server_sock = socket.socketpair()

    # the server uses a different psk than the client
    def run_the_server():
        try:
            run_server(server_sock, "server password".encode(), "server".encode())
        except Exception:
            pass

    thread = threading.Thread(target=run_the_server)
    thread.start()

    rejected = False
    try:
        run_client(client_sock, "client password".encode(), "client".encode())
    except ValueError:
        rejected = True

    client_sock.close()
    thread.join()
    server_sock.close()

    assert rejected, "client should reject a server with wrong psk"


if __name__ == "__main__":
    test_handshake_and_messaging()
    test_wrong_psk()
    print("pass")
