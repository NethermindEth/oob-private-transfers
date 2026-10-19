#!/usr/bin/env python3
"""S7-E4 per-epoch PIR read: runs the implementation's `oob-pir bench` (core/simplepir, full upstream SimplePIR
preprocessing over one epoch of m_e records, seeded A, every read checked byte-for-byte) under the benchlock, a
1-min-load gate and /usr/bin/time -l, and stores raw JSON with provenance under core/results/S7E4/<stamp>/.
Same code path as the provider's per-epoch PirServer (core/oobsvc/provider.py preprocess -> oob-pir setup, layout
'default' = upstream square); layout 'best' (one row group, hint 2.46 MB) is measured for comparison.

Usage: run_perepoch.py --count 4096 --reads 50 --layout default|best --stamp STAMP
"""
import sys
from pathlib import Path
sys.path.insert(0, str(Path(__file__).resolve().parents[3]))
from core.paths import TESTBED, BENCHLOCK
import argparse, datetime, json, os, platform, re, subprocess, sys, time

ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "..", ".."))
BIN = os.path.join(ROOT, "core", "simplepir", "oob-pir")
BENCHLOCK = str(BENCHLOCK)
LOADGATE = os.path.join(ROOT, "core", "experiments", "E5pir", "loadgate.py")
SCRATCH = str(TESTBED)


def sh(*cmd):
    try:
        return subprocess.run(cmd, capture_output=True, text=True, cwd=ROOT).stdout.strip()
    except Exception as e:  # noqa
        return f"unavailable: {e}"


def parse_time_l(text):
    out = {}
    m = re.search(r"([\d.]+) real\s+([\d.]+) user\s+([\d.]+) sys", text)
    if m:
        out.update(real_s=float(m.group(1)), user_s=float(m.group(2)), sys_s=float(m.group(3)))
    for key, pat in (("max_rss_bytes", r"(\d+)\s+maximum resident set size"),
                     ("peak_memory_footprint_bytes", r"(\d+)\s+peak memory footprint")):
        m = re.search(pat, text)
        if m:
            out[key] = int(m.group(1))
    return out


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--count", type=int, required=True)
    ap.add_argument("--reads", type=int, default=50)
    ap.add_argument("--layout", default="default", choices=["default", "best"])
    ap.add_argument("--stamp", required=True)
    ap.add_argument("--gate", type=float, default=8.0)
    ap.add_argument("--contaminated-above", type=float, default=12.0)
    ap.add_argument("--attempts", type=int, default=2)
    a = ap.parse_args()
    resdir = os.path.join(ROOT, "core", "results", "S7E4", a.stamp)
    os.makedirs(resdir, exist_ok=True)
    tb = os.path.join(SCRATCH, f"s7e4-{a.stamp}", f"N{a.count}-{a.layout}")
    os.makedirs(tb, exist_ok=True)
    req = {"op": "bench", "count": a.count, "width": 736, "reads": a.reads, "layout": a.layout, "out_dir": tb,
           "label": f"S7E4 per-epoch m_e={a.count} {a.layout}"}
    for attempt in range(1, a.attempts + 1):
        if one(a, req, resdir, attempt):
            break


def one(a, req, resdir, attempt):
    t_pre = time.time()
    while os.getloadavg()[0] > a.gate and time.time() - t_pre < 1800:
        time.sleep(15)
    cmd = [BENCHLOCK, sys.executable, LOADGATE, "--gate", str(a.gate), "--max-wait", "600", "--",
           "/usr/bin/time", "-l", BIN]
    meta = {"experiment": "S7E4-per-epoch", "command": " ".join(sys.argv), "worker_cmd": cmd, "request": req,
            "git_commit": sh("git", "rev-parse", "HEAD"),
            "git_dirty_simplepir": bool(sh("git", "status", "--porcelain", "--", "core/simplepir/oobpir",
                                           "core/simplepir/main.go", "core/simplepir/bench.go")),
            "binary_sha256": sh("shasum", "-a", "256", BIN).split(" ")[0],
            "hardware": {"cpu": sh("sysctl", "-n", "machdep.cpu.brand_string"), "ncpu": sh("sysctl", "-n", "hw.ncpu"),
                         "memsize": sh("sysctl", "-n", "hw.memsize"), "machine": platform.machine()},
            "load_avg_at_submit": os.getloadavg(), "started": datetime.datetime.now().isoformat()}
    t0 = time.time()
    p = subprocess.run(cmd, input=json.dumps(req) + "\n", capture_output=True, text=True)
    meta["wall_seconds_incl_lock_wait"] = time.time() - t0
    meta["load_avg_at_end"] = os.getloadavg()
    meta["returncode"] = p.returncode
    meta["time_l"] = parse_time_l(p.stderr)
    gate = [l for l in p.stderr.splitlines() if l.startswith("LOADGATE ")]
    meta["load_gate"] = json.loads(gate[0][len("LOADGATE "):]) if gate else None
    start_load = meta["load_gate"]["load_at_start"][0] if meta["load_gate"] else None
    meta["contaminated"] = bool(start_load is None or start_load > a.gate or meta["load_avg_at_end"][0] > a.contaminated_above)
    meta["contamination_rule"] = f"1-min load at start (inside lock) > {a.gate} or at end > {a.contaminated_above}"
    meta["attempt"] = attempt
    try:
        resp = json.loads(p.stdout.strip().splitlines()[-1])
    except Exception as e:
        resp = {"error": f"no JSON output: {e}", "stdout_tail": p.stdout[-2000:]}
    meta["result"], meta["error"] = resp.get("result"), resp.get("error")
    name = f"perepoch-N{a.count}-{a.layout}" + (f"-contaminated-{attempt}" if meta["contaminated"] else "") + ".json"
    with open(os.path.join(resdir, name), "w") as f:
        json.dump(meta, f, indent=1)
    r = meta["result"] or {}
    print(json.dumps({"file": name, "error": meta["error"], "failures": r.get("failures"), "reads": r.get("reads"),
                      "contaminated": meta["contaminated"], "load_gate": meta["load_gate"],
                      "load_end": meta["load_avg_at_end"], "time_l": meta["time_l"]}), flush=True)
    return not meta["contaminated"]


if __name__ == "__main__":
    main()
