#!/usr/bin/env python3
"""S7-E2: admission proof cost (P1 full binding, depth 32) for the new section 7.

Run the WHOLE driver under the lock (it assumes exclusive use of the host):
    scripts/benchlock .venv/bin/python core/experiments/S7E2/run_s7e2.py [--quick]

Steps (each a separate process, wrapped in /usr/bin/time -l for peak RSS; load average recorded before/after):
  breakdown_d{8,16,32}   rows/cells per relation condition (s7e2-bench breakdown; no timing)
  bench_t12              prove (default rayon threads = 12) + verify + fresh setup; dumps proofs
  bench_t1               same with RAYON_NUM_THREADS=1, cached params
  batch_t12, batch_t1    BatchVerifier, batches 1/8/32/128
  tput_p{1,2,4,8,12}     P concurrent `oob-admission --role verifier` JSON-lines workers (RAYON_NUM_THREADS=1 each),
                         each verifying K proofs from the dump, started together after all workers are ready
Raw JSON goes to core/results/S7E2/<timestamp>/.
"""
import sys
from pathlib import Path
sys.path.insert(0, str(Path(__file__).resolve().parents[3]))
from core.paths import HALO_KEYS
import argparse, datetime, json, os, platform, re, subprocess, sys, threading, time

ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), '..', '..', '..'))
CRATE = os.path.join(ROOT, 'core', 'halo2')
BENCH = os.path.join(CRATE, 'target', 'release', 's7e2-bench')
WORKER = os.path.join(CRATE, 'target', 'release', 'oob-admission')
KEYS = str(HALO_KEYS)
LOAD_START_MAX, LOAD_END_FLAG = 8.0, 12.0


def sh(*cmd, cwd=None):
    try:
        return subprocess.run(cmd, cwd=cwd, capture_output=True, text=True).stdout.strip()
    except Exception as e:  # noqa
        return f'error: {e}'


def meta(argv):
    return {
        'git_commit': sh('git', 'rev-parse', 'HEAD', cwd=ROOT),
        'git_dirty_paths': sh('git', 'status', '--porcelain', '--', 'core/halo2', 'core/experiments/S7E2', cwd=ROOT),
        'command_line': argv, 'rustc': sh('rustc', '--version'),
        'cpu': sh('sysctl', '-n', 'machdep.cpu.brand_string'), 'logical_cpus': sh('sysctl', '-n', 'hw.ncpu'),
        'perf_cores': sh('sysctl', '-n', 'hw.perflevel0.physicalcpu'), 'eff_cores': sh('sysctl', '-n', 'hw.perflevel1.physicalcpu'),
        'memory_bytes': sh('sysctl', '-n', 'hw.memsize'), 'os': sh('sw_vers'), 'kernel': platform.release(),
        'load_avg_at_start': os.getloadavg(), 'started': datetime.datetime.now().isoformat(timespec='seconds'),
    }


def load_gate():
    waited = 0
    while os.getloadavg()[0] > LOAD_START_MAX:
        print(f'load gate: 1-min load {os.getloadavg()[0]:.1f} > {LOAD_START_MAX}; waiting 20 s', flush=True)
        time.sleep(20)
        waited += 20
    return waited


def parse_time_l(stderr):
    out = {}
    m = re.search(r'(\d+)\s+maximum resident set size', stderr)
    if m: out['max_rss_bytes'] = int(m.group(1))
    m = re.search(r'(\d+)\s+peak memory footprint', stderr)
    if m: out['peak_memory_footprint_bytes'] = int(m.group(1))
    m = re.search(r'([\d.]+) real\s+([\d.]+) user\s+([\d.]+) sys', stderr)
    if m: out['real_s'], out['user_s'], out['sys_s'] = map(float, m.groups())
    return out


def run_bench(outdir, name, args, env_extra):
    waited = load_gate()
    raw = os.path.join(outdir, f'{name}.raw.json')
    cmd = ['/usr/bin/time', '-l', BENCH] + args + ['--out', raw]
    la0 = os.getloadavg(); t0 = time.time()
    p = subprocess.run(cmd, env=dict(os.environ, **env_extra), capture_output=True, text=True)
    wall = time.time() - t0; la1 = os.getloadavg()
    rec = {'name': name, 'cmd': cmd, 'env': env_extra, 'returncode': p.returncode, 'load_gate_waited_s': waited,
           'load_avg_start': la0, 'load_avg_end': la1, 'contaminated': la1[0] > LOAD_END_FLAG, 'wall_s': wall,
           'time_l': parse_time_l(p.stderr), 'stderr_tail': p.stderr[-3000:]}
    if p.returncode == 0 and os.path.exists(raw):
        rec['result'] = json.load(open(raw))
    json.dump(rec, open(os.path.join(outdir, f'{name}.json'), 'w'), indent=2)
    print(f"{name}: rc={p.returncode} wall={wall:.0f}s load {la0[0]:.1f}->{la1[0]:.1f} "
          f"rss={rec['time_l'].get('max_rss_bytes', 0) / 1e6:.0f}MB", flush=True)
    return rec


class Worker:
    def __init__(self, idx):
        env = dict(os.environ, RAYON_NUM_THREADS='1')
        self.p = subprocess.Popen(['/usr/bin/time', '-l', WORKER, '--keys', KEYS, '--depth', '32', '--variant', 'full',
                                   '--role', 'verifier'], stdin=subprocess.PIPE, stdout=subprocess.PIPE,
                                  stderr=subprocess.PIPE, text=True, env=env, bufsize=1)
        self.idx = idx
        self.ready = threading.Event()
        self.stderr = []
        threading.Thread(target=self._err, daemon=True).start()

    def _err(self):
        for line in self.p.stderr:
            self.stderr.append(line)
            if 'oob-admission ready' in line:
                self.ready.set()

    def verify(self, item):
        self.p.stdin.write(json.dumps({'op': 'verify', 'public': item['public'], 'proof': item['proof']}) + '\n')
        self.p.stdin.flush()
        return json.loads(self.p.stdout.readline())

    def close(self):
        self.p.stdin.close()
        self.p.wait(timeout=60)
        time.sleep(0.2)
        return parse_time_l(''.join(self.stderr))


def run_tput(outdir, P, K, items):
    waited = load_gate()
    la0 = os.getloadavg()
    ws = [Worker(i) for i in range(P)]
    for w in ws:
        if not w.ready.wait(timeout=300):
            raise SystemExit('verifier worker did not become ready')
    go = threading.Barrier(P + 1)
    res = [None] * P

    def body(w):
        go.wait()
        s = []
        t0 = time.perf_counter()
        for i in range(K):
            it = items[(w.idx * 7 + i) % len(items)]
            t = time.perf_counter()
            r = w.verify(it)['result']
            s.append({'client_s': time.perf_counter() - t, 'worker_s': r['verify_seconds'], 'valid': r['valid']})
        res[w.idx] = {'start': t0, 'end': time.perf_counter(), 'samples': s}

    ths = [threading.Thread(target=body, args=(w,)) for w in ws]
    for t in ths: t.start()
    go.wait()
    t_go = time.perf_counter()
    for t in ths: t.join()
    wall = max(r['end'] for r in res) - t_go
    la1 = os.getloadavg()
    rss = [w.close() for w in ws]
    total = P * K
    valid = all(s['valid'] for r in res for s in r['samples'])
    rec = {'name': f'tput_p{P}', 'processes': P, 'proofs_per_process': K, 'rayon_threads_per_process': 1,
           'load_gate_waited_s': waited, 'load_avg_start': la0, 'load_avg_end': la1, 'contaminated': la1[0] > LOAD_END_FLAG,
           'wall_s': wall, 'total_verified': total, 'all_valid': valid, 'throughput_per_s': total / wall,
           'per_process': res, 'worker_time_l': rss}
    json.dump(rec, open(os.path.join(outdir, f'tput_p{P}.json'), 'w'), indent=2)
    print(f"tput_p{P}: {total} proofs in {wall:.2f}s = {total / wall:.2f}/s ({total / wall / P:.2f}/s/proc) "
          f"valid={valid} load {la0[0]:.1f}->{la1[0]:.1f}", flush=True)
    return rec


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument('--quick', action='store_true', help='smoke test only (tiny reps), NOT a measurement')
    ap.add_argument('--only', default='')
    a = ap.parse_args()
    for b in (BENCH, WORKER):
        if not os.path.exists(b):
            sys.exit(f'missing {b}: build core/halo2 in release mode first')
    stamp = datetime.datetime.now().strftime('%Y%m%dT%H%M%S')
    outdir = os.path.join(ROOT, 'core', 'results', 'S7E2', stamp + ('-quick' if a.quick else ''))
    os.makedirs(outdir)
    base = meta(sys.argv)
    json.dump(base, open(os.path.join(outdir, 'run_meta.json'), 'w'), indent=2)
    q = a.quick
    only = set(filter(None, a.only.split(',')))
    want = lambda n: not only or n in only
    for d in (8, 16, 32, 64):
        if want('breakdown'):
            run_bench(outdir, f'breakdown_d{d}', ['breakdown', '--depth', str(d)], {})
    dump = os.path.join(outdir, 'proofs_d32.json')
    if want('bench_t12'):
        run_bench(outdir, 'bench_t12', ['bench', '--depth', '32', '--prove-runs', '2' if q else '20',
                                        '--verify-runs', '4' if q else '60', '--fresh-params', '--keys', KEYS,
                                        '--dump', dump], {})
    if want('bench_t1'):
        run_bench(outdir, 'bench_t1', ['bench', '--depth', '32', '--prove-runs', '1' if q else '5',
                                       '--verify-runs', '2' if q else '20', '--keys', KEYS], {'RAYON_NUM_THREADS': '1'})
    if os.path.exists(dump):
        batches = '1,8' if q else '1,8,32,128'
        if want('batch'):
            run_bench(outdir, 'batch_t12', ['batchverify', '--depth', '32', '--proofs', dump, '--batches', batches,
                                            '--reps', '1' if q else '3', '--keys', KEYS], {})
            run_bench(outdir, 'batch_t1', ['batchverify', '--depth', '32', '--proofs', dump, '--batches', batches,
                                           '--reps', '1' if q else '3', '--keys', KEYS], {'RAYON_NUM_THREADS': '1'})
        if want('tput'):
            items = json.load(open(dump))
            for P in ((1, 2) if q else (1, 2, 4, 8, 12)):
                run_tput(outdir, P, 2 if q else 12, items)
    json.dump(dict(base, finished=datetime.datetime.now().isoformat(timespec='seconds'),
                   load_avg_at_end=os.getloadavg()), open(os.path.join(outdir, 'run_meta.json'), 'w'), indent=2)
    print('results in', outdir)


if __name__ == '__main__':
    main()
