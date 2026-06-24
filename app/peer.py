#chat over the secure channel

#first make a pre shared key file (do this once, keep it secret):


"""then run this on both terminals (copy psk.key to both):
python -m app.peer
it asks for the role, host, port, id and the psk file
"""
import socket
import threading

from protocol.handshake import run_client, run_server
from protocol.channel import seal, unseal
from protocol.messages import send_message, recv_message


def read_loop(sock, session, my_name):
    #runs in the background, decrypts and prints messages as they arrive
    try:
        while True:
            message = recv_message(sock)[0]
            text = unseal(session, message)
            print(text.decode())
    except ConnectionError:
        print("connection closed")


def chat(sock, session, my_name):
    #start the reader in the background, then send whatever we type
    threading.Thread(target=read_loop, args=(sock, session, my_name), daemon=True).start()
    while True:
        line = input(my_name + "> ")
        send_message(sock, [seal(session, line.encode())])#encrypt the line and send it


def main():
    #ask for the settings, then read the shared key file
    role = input("role (server/client): ")
    host = input("host: ")
    port = int(input("port: "))
    my_id = input("your id: ")
    psk_file = input("psk file: ")
    psk = open(psk_file, "rb").read()

    if role == "server":
        #wait for the client to connect, then run the handshake
        listener = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        listener.bind((host, port))
        listener.listen(1)
        print("waiting for a connection on " + host + ":" + str(port))
        conn, addr = listener.accept()
        print("connected to " + str(addr))
        session = run_server(conn, psk, my_id.encode())
    else:
        #dial the server, then run the handshake
        conn = socket.create_connection((host, port))
        session = run_client(conn, psk, my_id.encode())

    print("handshake complete - start chatting")
    chat(conn, session, my_id)


if __name__ == "__main__":
    main()
