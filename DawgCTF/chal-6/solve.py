"""Challenge 6 — Sneedham-Chucker.

Needham-Schroeder Public-Key between sneed (Alice endpoint, A) and chuck
(Bob endpoint, B). Classic Lowe man-in-the-middle: we run a parallel session
as "eve" against sneed while relaying to chuck.

  chuck -> sneed (via us):    pubC, chuck, certC          (we only capture)
  us(eve) -> sneed:           pubE, eve, certE
  sneed -> us:                {nA, pubA, sneed, certA}pubE          [we decrypt]
  us -> chuck:                {nA, pubA, sneed, certA}pubC          [re-encrypted]
  chuck -> us:                {nA, nB}pubA                           [opaque to us]
  us -> sneed:                {nA, nB}pubA (forwarded as {nA,nX}pubA)
  sneed -> us:                {nB}pubE                               [we decrypt -> nB]
  us -> chuck:                {nB}pubC                               [re-encrypted]
  chuck -> us:                {flag_nonce, {FLAG}h(nA+nB)}           [we decrypt]
"""
import sys, pathlib
sys.path.insert(0, str(pathlib.Path(__file__).resolve().parent.parent))
from client import new_instance, send_alice, send_bob, util


def parse(s: str):
    items = []
    for part in s.split("|"):
        t, _, v = part.partition(":")
        items.append((t, v))
    return items


def gen_keypair():
    kp = parse(util("gen_asym_key_pair", ""))
    return kp[1][1], kp[3][1]  # pub, priv


def get_cert(pub: str, name: str) -> str:
    return parse(util("get_cert", f"k:{pub}|n:{name}"))[0][1]


def asym_encrypt(pub: str, plaintext: str) -> str:
    return parse(util("asym_encrypt", f"k:{pub}|t:{plaintext}"))[0][1]


def asym_decrypt(priv: str, data: str) -> str:
    return util("asym_decrypt", f"k:{priv}|d:{data}")


def main():
    # 0. Eve identity.
    pub_e, priv_e = gen_keypair()
    cert_e = get_cert(pub_e, "eve")
    print(f"eve pub({len(pub_e)}) priv({len(priv_e)}) cert({len(cert_e)})")

    conn = new_instance(6)
    print(f"conn: {conn}")

    # 1. Pull chuck's (pubB, B, certB) out of Bob's first send.
    bob1 = send_bob(conn, "")
    print(f"\nchuck step1: {bob1}")
    bi = dict((t, v) for t, v in parse(bob1))
    pub_c, cert_c = bi["k"], bi["d"]

    # 2. Walk up to sneed as "eve".
    alice1 = send_alice(conn, f"k:{pub_e}|n:eve|d:{cert_e}")
    print(f"\nsneed step2 (ct): {alice1[:80]}...")
    ct_a = parse(alice1)[0][1]
    pt_a = asym_decrypt(priv_e, ct_a)
    print(f"sneed step2 plaintext: {pt_a}")
    ai = parse(pt_a)
    nA = ai[0][1]
    pub_a = ai[1][1]
    cert_a = ai[3][1]
    print(f"nA = {nA}")

    # 3. Re-seal for chuck and deliver to Bob's recv step.
    re_for_chuck = asym_encrypt(pub_c, f"d:{nA}|k:{pub_a}|n:sneed|d:{cert_a}")
    bob2 = send_bob(conn, f"d:{re_for_chuck}")
    print(f"\nchuck step3: {bob2[:80]}...")
    ct_b = parse(bob2)[0][1]
    # Opaque to us: {nA, nB}pubA. Hand it straight to sneed as her recv of {nA,nX}pubA.
    alice2 = send_alice(conn, f"d:{ct_b}")
    print(f"\nsneed step4 (ct): {alice2[:80]}...")
    ct_nb = parse(alice2)[0][1]
    pt_nb = asym_decrypt(priv_e, ct_nb)
    print(f"sneed step4 plaintext: {pt_nb}")
    nB = parse(pt_nb)[0][1]
    print(f"nB = {nB}")

    # 4. Finish Bob: he wants {nB}pubB.
    seal_nb = asym_encrypt(pub_c, f"d:{nB}")
    bob3 = send_bob(conn, f"d:{seal_nb}")
    print(f"\nchuck step5: {bob3}")

    # 5. Flag is sym-encrypted under h(nA || nB).
    sym_key = parse(util("hash_data", f"d:{nA}{nB}"))[0][1]
    print(f"sym_key = {sym_key}")
    ct_flag = parse(bob3)[0][1]
    # Protocol writes {FLAG}h(nA+nB) with no explicit nonce. The server uses the
    # first 12 bytes of h(nA+nB) as the AEAD nonce and all 32 bytes as the key.
    nonce = sym_key[:24]
    flag = util("sym_decrypt", f"k:{sym_key}|d:{nonce}|d:{ct_flag}")
    print(f"\nFLAG: {flag}")


if __name__ == "__main__":
    main()
