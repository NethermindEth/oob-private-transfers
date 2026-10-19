#!/usr/bin/env python3
"""Load gate, run inside the benchlock: wait until the 1-min load average is <= GATE (default 8), record the wait
and the load, then exec the command. Writes one JSON line to stderr prefixed with 'LOADGATE '.
Usage: loadgate.py [--gate 8] [--max-wait 2700] -- cmd args..."""
import json, os, sys, time
args = sys.argv[1:]
gate, max_wait = 8.0, 2700.0
while args and args[0] != "--":
    if args[0] == "--gate":
        gate = float(args[1]); args = args[2:]
    elif args[0] == "--max-wait":
        max_wait = float(args[1]); args = args[2:]
    else:
        sys.exit(__doc__)
args = args[1:]
t0 = time.time()
while os.getloadavg()[0] > gate and time.time() - t0 < max_wait:
    time.sleep(10)
la = os.getloadavg()
sys.stderr.write("LOADGATE " + json.dumps({"gate": gate, "waited_s": round(time.time() - t0, 1), "load_at_start": la,
                                            "gate_timeout": la[0] > gate}) + "\n")
sys.stderr.flush()
os.execv(args[0], args)
