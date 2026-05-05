"""Challenge 9 — Oracle

Alice loops in her recv-send state: given {{m}pubA, X}pubA, she decrypts the
inner {m}pubA with privA and re-encrypts m under pubX. That is a full
decryption oracle for anything encrypted under pubA — any ciphertext we stuff
into the "inner" slot comes back re-encrypted under a key we control.

Bob's flag message is pubB, B, certB, {{[FLAG]}pubA, B}pubA, A. Two oracle
calls: first peel the outer wrapper (get d:<{FLAG}pubA>|n:bob as plaintext),
then decrypt {FLAG}pubA to recover the flag.
"""
import sys, pathlib
sys.path.insert(0, str(pathlib.Path(__file__).resolve().parent.parent))
from client import new_instance, send_alice, send_bob, util


def parse(content):
    out = {}
    for item in content.split("|"):
        t, _, v = item.partition(":")
        out.setdefault(t, []).append(v)
    return out


def d_val(resp):
    return parse(resp)["d"][0]


def oracle(conn, pub_a, pub_e, priv_e, cert_e, inner_ct):
    """Hand Alice inner_ct as her '{m}pubA' slot; recover plaintext m as raw content."""
    pt = f"d:{inner_ct}|n:eve"
    outer = d_val(util("asym_encrypt", f"k:{pub_a}|t:{pt}"))
    msg = f"k:{pub_e}|n:eve|d:{cert_e}|d:{outer}|n:alice"
    resp = send_alice(conn, msg)
    print("  alice ->", resp[:100], "...")
    # resp: k:pubA|n:alice|d:certA|d:<sent>|n:eve
    sent = parse(resp)["d"][1]
    # sent decrypts to "d:<ct_m>|n:alice"
    dec_outer = util("asym_decrypt", f"k:{priv_e}|d:{sent}")
    print("  dec_outer:", dec_outer[:100], "...")
    ct_m = parse(dec_outer)["d"][0]
    # ct_m decrypts to the plaintext m (whatever format Alice gave)
    return util("asym_decrypt", f"k:{priv_e}|d:{ct_m}")


def main():
    conn = new_instance(9)
    print("conn:", conn)

    alice_greet = send_alice(conn, "")
    print("alice ->", alice_greet[:100], "...")
    pub_a = parse(alice_greet)["k"][0]

    bob_resp = send_bob(conn, alice_greet)
    print("bob ->", bob_resp[:100], "...")
    # bob: k:pubB|n:bob|d:certB|d:<bob_outer>|n:alice
    bob_outer = parse(bob_resp)["d"][1]

    kp = parse(util("gen_asym_key_pair", ""))
    pub_e, priv_e = kp["k"][0], kp["k"][1]
    cert_e = d_val(util("get_cert", f"k:{pub_e}|n:eve"))

    print("[1] peeling Bob's outer wrapper")
    peeled = oracle(conn, pub_a, pub_e, priv_e, cert_e, bob_outer)
    print("peeled:", peeled[:120], "...")
    # peeled = "d:<{FLAG}pubA>|n:bob"
    flag_ct = parse(peeled)["d"][0]

    print("[2] decrypting {FLAG}pubA")
    flag = oracle(conn, pub_a, pub_e, priv_e, cert_e, flag_ct)
    print("FLAG:", flag)


if __name__ == "__main__":
    main()
