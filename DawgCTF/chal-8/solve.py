"""Challenge 8 — Reflection.

Script (Alice and Bob are both in the *same* initiator role):

  Alice send: pubA, alice, certA
  Bob   send: pubB, bob, certB
  Alice recv: pubX, X, certX, nX1
  Bob   recv: pubA, A, certA, nA
  Alice send: nA, {X, nX1, nA}privA
  Bob   send: nB, {A, nA, nB}privB
  Alice recv: nX2, {A, nA, nX2}privX
  Bob   recv: nA2, {A, nB, nA2}privA
  Bob   send: [FLAG]

Two things matter for chal-8:

1) /util/get_cert's denylist is case-sensitive. "alice" is blocked but
   "Alice" sails right through, so we can mint a cert that binds ANY key we
   want to the name "Alice". Bob's step-2 name check is case-insensitive, so
   he accepts it as his long-lost peer.

2) Inside the server, entity sig/verify text uses the RECEIVER's own name
   as the first field, not the peer's. Bob's step-4 check therefore wants a
   signature under "pubA" over the literal text `n:bob|d:{nB}|d:{nA2}` —
   NOT `n:alice|...` as the script `{A, nB, nA2}privA` would suggest. (This
   is why a pure A/B reflection — forcing real Alice to sign with X=alice —
   fails: real Alice's sig text starts with `n:alice`.)

Combine the two: give Bob `(pub_e, "Alice", cert_e, any_nA)`. Bob stores
pub_e as his "pubA" and advances. He emits `nB, sig_bob`. We forge the
step-4 sig under priv_e (which Bob now believes is privA) over
`n:bob|d:{nB}|d:{nA_in}`. Bob verifies against the pub_e he stored and
hands over the flag.
"""
import sys, pathlib
sys.path.insert(0, str(pathlib.Path(__file__).resolve().parent.parent))
from client import new_instance, send_bob, util


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
    # 1. Mint a key we control and cert it as "Alice" (capital bypass).
    pub_e, priv_e = gen_keypair()
    cert_e = get_cert(pub_e, "Alice")
    print(f"forged peer ready: pub_e={pub_e[:40]}...")
    print(f"                   cert_e={cert_e[:40]}...")

    conn = new_instance(8)
    print(f"\nconn: {conn}")

    # 2. Walk Bob through step 1 (his opening send) so we see his wire format.
    b1 = send_bob(conn, "")
    print(f"\nbob step1: {b1}")

    # 3. Feed Bob his step-2 recv: pubX=pub_e, name="Alice", cert=cert_e,
    #    nA = arbitrary (we pick it; Bob treats it as alice's nonce).
    nA_in = "cd" * 32
    step2 = f"k:{pub_e}|n:Alice|d:{cert_e}|d:{nA_in}"
    print(f"\n-> bob (step2): {step2[:80]}...")
    b2 = send_bob(conn, step2)
    print(f"<- bob step3: {b2}")

    # 4. Extract Bob's fresh nonce nB from his step-3 send.
    ds = [v for t, v in parse(b2) if t == "d"]
    nB = ds[0]
    print(f"nB = {nB}")

    # 5. Forge the step-4 signature. Bob's verification text uses HIS own
    #    name ("bob") as the first field, not the peer's.
    sig_text = f"n:bob|d:{nB}|d:{nA_in}"
    sig = asym_sign(priv_e, sig_text)
    print(f"\nforged sig over {sig_text}")
    print(f"sig = {sig[:60]}...")

    # 6. Deliver Bob's step-4 recv: nA2 (we claim nA_in), then the sig.
    step4 = f"d:{nA_in}|d:{sig}"
    print(f"\n-> bob (step4): {step4[:80]}...")
    flag = send_bob(conn, step4)
    print(f"<- bob step5: {flag}")


if __name__ == "__main__":
    main()
