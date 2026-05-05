"""Challenge 1: Can You Hear Me?

Plaintext protocol — adversary just relays Alice's greeting to Bob and reads
Bob's reply containing the flag.
"""
import sys, pathlib
sys.path.insert(0, str(pathlib.Path(__file__).resolve().parent.parent))

from client import new_instance, send_alice, send_bob

conn_id = new_instance(1)
print(f"conn_id: {conn_id}")

alice_msg = send_alice(conn_id, "")
print(f"alice -> {alice_msg}")

bob_reply = send_bob(conn_id, alice_msg)
print(f"bob   -> {bob_reply}")
