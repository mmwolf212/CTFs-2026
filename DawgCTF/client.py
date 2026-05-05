"""Reusable client for protocols.live challenges."""
import json
import urllib.request

BASE = "https://protocols.live"


def _post(path: str, payload: dict) -> dict:
    req = urllib.request.Request(
        BASE + path,
        data=json.dumps(payload).encode(),
        headers={"Content-Type": "application/json"},
        method="POST",
    )
    with urllib.request.urlopen(req) as r:
        return json.loads(r.read().decode())


def new_instance(chal_no: int) -> str:
    return _post(f"/model/{chal_no}", {})["conn_id"]


def send_alice(conn_id: str, content: str) -> str:
    return _post("/alice", {"conn_id": conn_id, "content": content})["content"]


def send_bob(conn_id: str, content: str) -> str:
    return _post("/bob", {"conn_id": conn_id, "content": content})["content"]


def util(name: str, content: str) -> str:
    return _post(f"/util/{name}", {"conn_id": 0, "content": content})["content"]
