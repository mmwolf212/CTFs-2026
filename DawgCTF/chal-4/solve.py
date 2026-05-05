"""Challenge 4 — Real Security!

Alice sends Bob a symmetric key + nonce in the clear and asks Bob to encrypt
the flag under them. Since the key and nonce are exposed on the wire, any
eavesdropper can decrypt the response.
"""
import sys, pathlib
sys.path.insert(0, str(pathlib.Path(__file__).resolve().parent.parent))
from client import new_instance, send_alice, send_bob, util


def parse(content: str) -> dict:
    out = {}
    for item in content.split("|"):
        t, _, v = item.partition(":")
        out.setdefault(t, []).append(v)
    return out


def main():
    conn = new_instance(4)
    print("conn_id:", conn)

    alice_msg = send_alice(conn, "")
    print("alice ->", alice_msg)

    parts = parse(alice_msg)
    key = parts["k"][0]
    nonce = parts["d"][0]
    print("key:", key)
    print("nonce:", nonce)

    bob_msg = send_bob(conn, alice_msg)
    print("bob ->", bob_msg)

    ct = parse(bob_msg)["d"][0]
    flag = util("sym_decrypt", f"k:{key}|d:{nonce}|d:{ct}")
    print("FLAG:", flag)


if __name__ == "__main__":
    main()
