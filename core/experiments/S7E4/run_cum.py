#!/usr/bin/env python3
"""S7-E4 cumulative-database points: runs s7e4bench (core/simplepir/cmd/s7e4bench, built into this dir) under the
benchlock, the 1-min-load gate and /usr/bin/time -l; raw JSON with provenance to core/results/S7E4/<stamp>/.

Usage: run_cum.py --stamp S -- -mode ra -count 16384 -cols 4096 -epochs 5 -reads 10
       run_cum.py --stamp S -- -mode cadelta -count 4096 -me 1024
"""
import sys
from pathlib import Path
sys.path.insert(0, str(Path(__file__).resolve().parents[3]))
from core.paths import TESTBED, BENCHLOCK
import datetime, json, os, platform, subprocess, sys, time

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.abspath(os.path.join(HERE, "..", "..", ".."))
BIN = os.path.join(HERE, "s7e4bench")
BENCHLOCK = str(BENCHLOCK)
LOADGATE = os.path.join(ROOT, "core", "experiments", "E5pir", "loadgate.py")
sys.path.insert(0, HERE)
from run_perepoch import parse_time_l, sh  # noqa: E402


def main():
    i = sys.argv.index("--")
    stamp = sys.argv[sys.argv.index("--stamp") + 1]
    args = sys.argv[i + 1:]
    resdir = os.path.join(ROOT, "core", "results", "S7E4", stamp)
    os.makedirs(resdir, exist_ok=True)
    tmp = os.path.join(str(TESTBED), f"s7e4-{stamp}", "cum")
    os.makedirs(tmp, exist_ok=True)
    name = "cum-" + "-".join(a.lstrip("-") for a in args)
    for attempt in (1, 2):
        t_pre = time.time()
        while os.getloadavg()[0] > 8 and time.time() - t_pre < 1800:
            time.sleep(15)
        cmd = [BENCHLOCK, sys.executable, LOADGATE, "--gate", "8", "--max-wait", "600", "--", "/usr/bin/time", "-l",
               BIN, *args, "-tmp", tmp]
        meta = {"experiment": "S7E4-cumulative", "command": " ".join(sys.argv), "worker_cmd": cmd,
                "git_commit": sh("git", "rev-parse", "HEAD"),
                "binary_sha256": sh("shasum", "-a", "256", BIN).split(" ")[0],
                "hardware": {"cpu": sh("sysctl", "-n", "machdep.cpu.brand_string"), "ncpu": sh("sysctl", "-n", "hw.ncpu"),
                             "memsize": sh("sysctl", "-n", "hw.memsize"), "machine": platform.machine()},
                "load_avg_at_submit": os.getloadavg(), "started": datetime.datetime.now().isoformat()}
        p = subprocess.run(cmd, capture_output=True, text=True)
        meta["load_avg_at_end"] = os.getloadavg()
        meta["returncode"] = p.returncode
        meta["time_l"] = parse_time_l(p.stderr)
        gate = [l for l in p.stderr.splitlines() if l.startswith("LOADGATE ")]
        meta["load_gate"] = json.loads(gate[0][9:]) if gate else None
        sl = meta["load_gate"]["load_at_start"][0] if meta["load_gate"] else None
        meta["contaminated"] = bool(sl is None or sl > 8 or meta["load_avg_at_end"][0] > 12)
        try:
            resp = json.loads(p.stdout.strip().splitlines()[-1])
        except Exception as e:
            resp = {"error": f"no JSON: {e}", "stderr_tail": p.stderr[-2000:]}
        meta["result"], meta["error"] = resp.get("result"), resp.get("error")
        fn = name + (f"-contaminated-{attempt}" if meta["contaminated"] else "") + ".json"
        json.dump(meta, open(os.path.join(resdir, fn), "w"), indent=1)
        r = meta["result"] or {}
        print(json.dumps({"file": fn, "error": meta["error"], "failures": r.get("failures"),
                          "hint_row_check": r.get("hint_row_check"), "delta_ok": r.get("delta_equals_DBnew_times_Anew"),
                          "contaminated": meta["contaminated"], "time_l": meta["time_l"]}), flush=True)
        if not meta["contaminated"]:
            break


if __name__ == "__main__":
    main()
