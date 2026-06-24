"""helpers for sending and receiving messages over a TCP socket.
each message is a list of byte string fields, we put a 2byte length in front
of every field, and a 4byte length in front of the whole message, so the
other side always knows exactly how many bytes to read.
"""

def recv_all(sock, n):
    #keep reading until we have exactly n bytes
    data = b""
    while len(data) < n:
        chunk = sock.recv(n - len(data))
        if len(chunk) == 0:
            raise ConnectionError("connection closed")
        data += chunk
    return data


def send_message(sock, fields):
    # fields is a list of byte strings
    body = b""
    for field in fields:
        body += len(field).to_bytes(2, "big") + field
    sock.sendall(len(body).to_bytes(4, "big") + body)


def recv_message(sock):
    #read one whole message and split it back into its fields
    total = int.from_bytes(recv_all(sock, 4), "big")
    body = recv_all(sock, total)
    fields = []
    i = 0
    while i < len(body):
        length = int.from_bytes(body[i:i + 2], "big")
        i += 2
        fields.append(body[i:i + length])
        i += length
    return fields
