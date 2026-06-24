"""the handshake transcript is a combination fo the handshake values
both sides build the exact same transcript and run HMAC over it with the
secret shared key, if an attacker changed anything, tags wont match 
and the handshake is aborted.
"""

def build_transcript(version, client_id, server_id, client_pub, server_pub):
    parts = [version, client_id, server_id, client_pub, server_pub]
    out = b""
    for part in parts:
        out += len(part).to_bytes(2, "big") + part# 2byte length (big endian) then part
    return out
