#!/usr/bin/env python3
"""Two-process round trip for oob-pir: a server process (setup/answer) and a
separate client process (load/query/recover), talking only via the JSON-lines
interface and files (hint.bin, public.json). Usage: roundtrip.py [count] [reads]"""
import sys
from pathlib import Path
sys.path.insert(0, str(Path(__file__).resolve().parents[2]))
from core.paths import TESTBED
import base64, hashlib, json, os, subprocess, sys, tempfile

BIN = os.path.join(os.path.dirname(os.path.abspath(__file__)), "oob-pir")
W = 736


class Worker:
    def __init__(self):
        self.p = subprocess.Popen([BIN], stdin=subprocess.PIPE, stdout=subprocess.PIPE, text=True)

    def call(self, **req):
        self.p.stdin.write(json.dumps(req) + "\n")
        self.p.stdin.flush()
        return json.loads(self.p.stdout.readline())

    def close(self):
        self.p.stdin.close()
        self.p.wait()


def main():
    count = int(sys.argv[1]) if len(sys.argv) > 1 else 1000
    reads = int(sys.argv[2]) if len(sys.argv) > 2 else 20
    base = str(TESTBED)
    os.makedirs(base, exist_ok=True)
    d = tempfile.mkdtemp(prefix="pir-roundtrip-", dir=base)
    recs = os.urandom(count * W)
    rf = os.path.join(d, "records.bin")
    open(rf, "wb").write(recs)
    seed_a = hashlib.sha256(b"OOB-A" + b"\x11" * 32 + (7).to_bytes(8, "big")).hexdigest()
    srv, cli = Worker(), Worker()
    r = srv.call(op="setup", records_file=rf, count=count, width=W, seed_A=seed_a, out_dir=d, epoch_id="7")
    assert "result" in r, r
    print("setup:", {k: r["result"][k] for k in ("hint_bytes", "public_bytes", "setup_seconds")})
    r = cli.call(op="load", public_json=os.path.join(d, "public.json"), hint_file=os.path.join(d, "hint.bin"))
    assert "result" in r, r
    print("load:", {k: r["result"][k] for k in ("client_setup_seconds", "hint_bytes", "public_bytes")})
    idxs = [0, count - 1] + [int.from_bytes(os.urandom(4), "big") % count for _ in range(reads - 2)]
    for i in idxs:
        rec = recs[i * W:(i + 1) * W]
        dig = hashlib.sha256(b"OOB-rec-v1" + rec).hexdigest()
        q = cli.call(op="query", index=i)["result"]
        a = srv.call(op="answer", epoch_id="7", query=q["query"])["result"]
        out = cli.call(op="recover", state_id=q["state_id"], answer=a["answer"], expect_digest=dig)["result"]
        assert base64.b64decode(out["record"]) == rec and out["digest_ok"], i
    # negative cases
    assert "error" in cli.call(op="query", index=count)
    assert "error" in srv.call(op="answer", epoch_id="7", query=base64.b64encode(b"OQv1\x00\x00\x00\x00").decode())
    t = min(1, count - 1)
    q = cli.call(op="query", index=t)["result"]
    a = srv.call(op="answer", epoch_id="7", query=q["query"])["result"]
    raw = bytearray(base64.b64decode(a["answer"]))
    for j in range(8, len(raw), 4):
        raw[j + 3] ^= 0x55
    out = cli.call(op="recover", state_id=q["state_id"], answer=base64.b64encode(bytes(raw)).decode(),
                   expect_digest=hashlib.sha256(b"OOB-rec-v1" + recs[t * W:(t + 1) * W]).hexdigest())
    assert "error" in out or out["result"]["digest_ok"] is False, out
    print(f"OK: {len(idxs)} reads verified across two processes; tampered answer -> "
          f"{'decode error' if 'error' in out else 'digest mismatch'}")
    srv.close(); cli.close()


if __name__ == "__main__":
    main()
