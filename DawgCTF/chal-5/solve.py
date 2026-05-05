"""Challenge 5 — Is This Real?

Bob accepts any public key in Alice's greeting and encrypts the flag under it.
Generate our own keypair, hand Bob our pub, decrypt his ciphertext with our priv.
"""
import sys, pathlib
sys.path.insert(0, str(pathlib.Path(__file__).resolve().parent.parent))
from client import new_instance, send_bob, util


def parse(content: str) -> dict:
    out = {}
    for item in content.split("|"):
        t, _, v = item.partition(":")
        out.setdefault(t, []).append(v)
    return out


def main():
    kp = parse(util("gen_asym_key_pair", ""))
    pub, priv = kp["k"][0], kp["k"][1]
    print("pub:", pub[:32], "...")

    conn = new_instance(5)
    print("conn_id:", conn)

    greeting = (
        "t:Hello|n:bob|t:this is|n:alice"
        "|t:send the flag encrypted under this asymetric key"
        f"|k:{pub}"
    )
    bob_msg = send_bob(conn, greeting)
    print("bob ->", bob_msg)

    ct = parse(bob_msg)["d"][0]
    flag = util("asym_decrypt", f"k:{priv}|d:{ct}")
    print("FLAG:", flag)


if __name__ == "__main__":
    main()
