"""Challenge 2: Liar

Bob will only hand out the flag if the requester claims to be charlie.
No crypto, no signatures — the adversary rewrites the sender name from
alice to charlie before relaying to Bob.
"""
import sys, pathlib
sys.path.insert(0, str(pathlib.Path(__file__).resolve().parent.parent))

from client import new_instance, send_bob

conn_id = new_instance(2)
print(f"conn_id: {conn_id}")

forged = "t:Hello|n:bob|t:this is|n:charlie|t:give me the flag"
print(f"-> bob: {forged}")

reply = send_bob(conn_id, forged)
print(f"<- bob: {reply}")
