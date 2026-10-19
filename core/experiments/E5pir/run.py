#!/usr/bin/env python3
"""E5 PIR sweep driver. Runs `oob-pir bench` (full upstream SimplePIR
preprocessing, seeded A, every read checked) under the exclusive benchlock and
/usr/bin/time -l, and stores raw JSON with provenance under
core/results/E5pir/<timestamp>/.

Usage: run.py --count 4096 --reads 200 [--layout default|best] [--stamp STAMP] [--label L]
"""
import sys
from pathlib import Path
sys.path.insert(0, str(Path(__file__).resolve().parents[3]))
from core.paths import TESTBED, BENCHLOCK
import argparse, datetime, json, os, platform, re, subprocess, sys, time

ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "..", ".."))
BIN = os.path.join(ROOT, "core", "simplepir", "oob-pir")
BENCHLOCK = str(BENCHLOCK)
TESTBED = str(TESTBED)


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
    ap.add_argument("--reads", type=int, required=True)
    ap.add_argument("--cols", type=int, default=0)
    ap.add_argument("--layout", default="default", choices=["default", "best"])
    ap.add_argument("--stamp", default=datetime.datetime.now().strftime("%Y%m%dT%H%M%S"))
    ap.add_argument("--label", default="")
    ap.add_argument("--gate", type=float, default=8.0, help="1-min load required before timing (inside the lock)")
    ap.add_argument("--contaminated-above", type=float, default=12.0, help="end 1-min load marking a run contaminated")
    ap.add_argument("--attempts", type=int, default=3)
    a = ap.parse_args()
    resdir = os.path.join(ROOT, "core", "results", "E5pir", a.stamp)
    os.makedirs(resdir, exist_ok=True)
    tb = os.path.join(TESTBED, f"e5pir-{a.stamp}", f"N{a.count}-{a.layout}")
    os.makedirs(tb, exist_ok=True)
    req = {"op": "bench", "count": a.count, "width": 736, "reads": a.reads, "cols": a.cols, "layout": a.layout,
           "out_dir": tb, "label": a.label}
    for attempt in range(1, a.attempts + 1):
        clean = one(a, req, resdir, attempt)
        if clean:
            break


def one(a, req, resdir, attempt):
    # pre-gate outside the lock (do not hold the lock while waiting for system load to drop)
    t_pre = time.time()
    while os.getloadavg()[0] > a.gate and time.time() - t_pre < 2700:
        time.sleep(15)
    pre_wait = time.time() - t_pre
    cmd = [BENCHLOCK, sys.executable, os.path.join(os.path.dirname(os.path.abspath(__file__)), "loadgate.py"),
           "--gate", str(a.gate), "--max-wait", "600", "--", "/usr/bin/time", "-l", BIN]
    meta = {
        "experiment": "E5pir", "command": " ".join(sys.argv), "worker_cmd": cmd, "request": req,
        "git_commit": sh("git", "rev-parse", "HEAD"),
        "git_dirty": bool(sh("git", "status", "--porcelain", "--", "core/simplepir")),
        "binary_sha256": sh("shasum", "-a", "256", BIN).split(" ")[0],
        "versions": {"go": None,
                     "upstream": "github.com/ahenzinger/simplepir@e9020b03bf2872c75b8954e749e32408b5db87ed"},
        "hardware": {"cpu": sh("sysctl", "-n", "machdep.cpu.brand_string"), "ncpu": sh("sysctl", "-n", "hw.ncpu"),
                     "memsize": sh("sysctl", "-n", "hw.memsize"), "os": sh("sw_vers"), "machine": platform.machine()},
        "load_avg_at_submit": os.getloadavg(),
        "started": datetime.datetime.now().isoformat(),
    }
    t0 = time.time()
    p = subprocess.run(cmd, input=json.dumps(req) + "\n", capture_output=True, text=True)
    meta["wall_seconds_incl_lock_wait"] = time.time() - t0
    meta["load_avg_at_end"] = os.getloadavg()
    meta["returncode"] = p.returncode
    meta["time_l"] = parse_time_l(p.stderr)
    meta["stderr_tail"] = p.stderr[-3000:]
    gate = [l for l in p.stderr.splitlines() if l.startswith("LOADGATE ")]
    meta["load_gate"] = json.loads(gate[0][len("LOADGATE "):]) if gate else None
    start_load = meta["load_gate"]["load_at_start"][0] if meta["load_gate"] else None
    meta["contaminated"] = bool(start_load is None or start_load > a.gate or meta["load_avg_at_end"][0] > a.contaminated_above)
    meta["contamination_rule"] = f"1-min load at start (inside lock) > {a.gate} or at end > {a.contaminated_above}"
    meta["attempt"] = attempt
    meta["pre_gate_wait_s"] = pre_wait
    try:
        resp = json.loads(p.stdout.strip().splitlines()[-1])
    except Exception as e:  # recorded, not dropped
        resp = {"error": f"no JSON output: {e}", "stdout_tail": p.stdout[-2000:]}
    meta["result"] = resp.get("result")
    meta["error"] = resp.get("error")
    meta["versions"]["go"] = (meta["result"] or {}).get("go")
    name = f"pir-N{a.count}-{a.layout}.json"
    if meta["contaminated"]:
        name = f"pir-N{a.count}-{a.layout}-contaminated-{attempt}.json"
    with open(os.path.join(resdir, name), "w") as f:
        json.dump(meta, f, indent=1)
    r = meta["result"] or {}
    print(json.dumps({"file": os.path.join(resdir, name), "error": meta["error"], "failures": r.get("failures"),
                      "reads": r.get("reads"), "time_l": meta["time_l"], "contaminated": meta["contaminated"],
                      "load_gate": meta["load_gate"], "load_end": meta["load_avg_at_end"]}))
    return not meta["contaminated"]


if __name__ == "__main__":
    main()
