"""Challenge 3: Missing

Alice is absent from this instance, so only Bob has a script. Bob's first
step is a recv of the standard greeting; his next step is to send the flag.
We skip Alice entirely and hand Bob the greeting ourselves.
"""
import sys, pathlib
sys.path.insert(0, str(pathlib.Path(__file__).resolve().parent.parent))

from client import new_instance, send_bob

conn_id = new_instance(3)
print(f"conn_id: {conn_id}")

greeting = "t:Hello|n:bob|t:this is|n:alice|t:give me the flag"
print(f"-> bob: {greeting}")

reply = send_bob(conn_id, greeting)
print(f"<- bob: {reply}")
