"""Challenge 7 — Mediation.

Script (Alice = alice, Bob = bob):

  Alice send: pubA, alice, certA, nA
  Bob   recv: pubA, alice, certA, nA
  Bob   send: pubB, bob, certB, nB, {bob, nB, nA}privB
  Alice recv: pubX,   X,  certX, nX, {X,   nX, nA}privX     (any X)
  Alice send: {alice, nX, nA}privA
  Bob   recv: {alice, nB, nA}privA
  Bob   send: [FLAG]

Bob's final recv wants Alice's signature over (alice, nB, nA). Alice will
sign (alice, nX, nA) for whatever nX we convinced her came from her peer.
So: impersonate "eve" to Alice, but quote Bob's nonce nB as eve's nonce.
Alice then hands us the exact signature Bob will accept.
"""
import sys, pathlib
sys.path.insert(0, str(pathlib.Path(__file__).resolve().parent.parent))
from client import new_instance, send_alice, send_bob, util


def parse(s: str):
    return [tuple(p.split(":", 1)) for p in s.split("|")]


def gen_keypair():
    kp = parse(util("gen_asym_key_pair", ""))
    return kp[1][1], kp[3][1]  # pub, priv


def get_cert(pub: str, name: str) -> str:
    return parse(util("get_cert", f"k:{pub}|n:{name}"))[0][1]


def asym_sign(priv: str, text: str) -> str:
    return parse(util("asym_sign", f"k:{priv}|t:{text}"))[0][1]


def main():
    pub_e, priv_e = gen_keypair()
    cert_e = get_cert(pub_e, "eve")
    print(f"eve ready")

    conn = new_instance(7)
    print(f"conn: {conn}")

    # 1. Alice's opening send: pubA, alice, certA, nA
    a1 = send_alice(conn, "")
    print(f"\nalice step1: {a1}")
    ai = dict(parse(a1))
    nA = ai["d"]
    print(f"nA = {nA}")

    # 2. Bob's recv then send: pubB, bob, certB, nB, sigB
    b1 = send_bob(conn, a1)
    print(f"\nbob step2: {b1}")
    # Items: k:pubB | n:bob | d:certB | d:nB | d:sigB
    items = parse(b1)
    d_items = [v for t, v in items if t == "d"]
    cert_b, nB, sig_b = d_items[0], d_items[1], d_items[2]
    print(f"nB = {nB}")

    # 3. Feed Alice a forged recv as "eve" but with nX = nB.
    # Signature covers (eve, nB, nA). Canonical typed encoding.
    sig_e = asym_sign(priv_e, f"n:eve|d:{nB}|d:{nA}")
    forged = f"k:{pub_e}|n:eve|d:{cert_e}|d:{nB}|d:{sig_e}"
    print(f"\n-> alice (forged recv): {forged[:100]}...")
    a2 = send_alice(conn, forged)
    print(f"<- alice step3: {a2}")
    # Alice emits {alice, nX, nA}privA = sign(privA, "n:alice|d:nB|d:nA")
    sig_a = parse(a2)[0][1]
    print(f"sig_a = {sig_a[:60]}...")

    # 4. Bob's final recv wants exactly that signature.
    b2 = send_bob(conn, f"d:{sig_a}")
    print(f"\nbob step4: {b2}")


if __name__ == "__main__":
    main()
