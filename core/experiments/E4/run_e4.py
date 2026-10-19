#!/usr/bin/env python3
"""E4 admission-cost measurements + adversarial suite for core/halo2 (oob-admission relation v2).

Run the WHOLE driver under the exclusive lock:
    scripts/benchlock python3 core/experiments/E4/run_e4.py [--quick]

Per configuration it runs `/usr/bin/time -l e4-bench bench ...` (one process per configuration), records
load average before/after (load gate: waits while 1-min load > 8; flags end load > 12 as contaminated),
and writes raw JSON to core/results/E4/<timestamp>/. Nothing is aggregated here; make_table.py reads the files.
"""
import sys
from pathlib import Path
sys.path.insert(0, str(Path(__file__).resolve().parents[3]))
from core.paths import HALO_KEYS
import argparse, datetime, json, os, platform, re, subprocess, sys, time

ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), '..', '..', '..'))
CRATE = os.path.join(ROOT, 'core', 'halo2')
BENCH = os.path.join(CRATE, 'target', 'release', 'e4-bench')
KEYS = str(HALO_KEYS)
LOAD_START_MAX, LOAD_END_FLAG = 8.0, 12.0


def sh(*cmd, cwd=None):
    try:
        return subprocess.run(cmd, cwd=cwd, capture_output=True, text=True).stdout.strip()
    except Exception as e:  # noqa
        return f'error: {e}'


def meta(argv):
    lock = open(os.path.join(CRATE, 'Cargo.lock')).read()
    deps = {n: v for n, v in re.findall(r'name = "([^"]+)"\nversion = "([^"]+)"', lock)
            if n in ('halo2_proofs', 'halo2curves', 'ff', 'group', 'rayon', 'blake2b_simd', 'rand_core')}
    return {
        'git_commit': sh('git', 'rev-parse', 'HEAD', cwd=ROOT),
        'git_dirty': bool(sh('git', 'status', '--porcelain', '--', 'core/halo2', 'core/experiments/E4', cwd=ROOT)),
        'command_line': argv,
        'dependency_versions': deps,
        'rustc': sh('rustc', '--version'),
        'cpu': sh('sysctl', '-n', 'machdep.cpu.brand_string'),
        'logical_cpus': sh('sysctl', '-n', 'hw.ncpu'),
        'memory_bytes': sh('sysctl', '-n', 'hw.memsize'),
        'os': sh('sw_vers'),
        'kernel': platform.release(),
        'load_avg_at_start': os.getloadavg(),
        'started': datetime.datetime.now().isoformat(timespec='seconds'),
    }


def load_gate():
    waited = 0
    while os.getloadavg()[0] > LOAD_START_MAX:
        print(f'load gate: 1-min load {os.getloadavg()[0]:.1f} > {LOAD_START_MAX}; waiting 30 s', flush=True)
        time.sleep(30)
        waited += 30
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


def run(outdir, name, args, env_extra, base_meta):
    waited = load_gate()
    env = dict(os.environ, **env_extra)
    raw = os.path.join(outdir, f'{name}.bench.json')
    cmd = ['/usr/bin/time', '-l', BENCH] + args + ['--keys', KEYS, '--out', raw]
    la0 = os.getloadavg(); t0 = time.time()
    p = subprocess.run(cmd, env=env, capture_output=True, text=True)
    wall = time.time() - t0; la1 = os.getloadavg()
    rec = {'name': name, 'meta': base_meta, 'cmd': cmd, 'env': env_extra, 'returncode': p.returncode,
           'load_gate_waited_s': waited, 'load_avg_start': la0, 'load_avg_end': la1,
           'contaminated': la1[0] > LOAD_END_FLAG, 'wall_s': wall, 'time_l': parse_time_l(p.stderr),
           'stderr_tail': p.stderr[-4000:]}
    if p.returncode == 0 and os.path.exists(raw):
        rec['result'] = json.load(open(raw))
    json.dump(rec, open(os.path.join(outdir, f'{name}.json'), 'w'), indent=2)
    r = rec.get('result', {})
    s = r.get('samples', [])
    pv = sorted(x['prove_seconds'] for x in s)
    print(f"{name}: rc={p.returncode} wall={wall:.0f}s load {la0[0]:.1f}->{la1[0]:.1f}"
          f" rss={rec['time_l'].get('max_rss_bytes', 0)/2**20:.0f}MB"
          + (f" prove_med={pv[len(pv)//2]:.2f}s n={len(pv)}" if pv else '')
          + (f" adversarial={r.get('summary')}" if 'summary' in r else ''), flush=True)
    return rec


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument('--quick', action='store_true', help='2 runs per config (smoke test only)')
    ap.add_argument('--skip-build', action='store_true')
    ap.add_argument('--only', default='', help='comma-separated config names')
    a = ap.parse_args()
    if not a.skip_build:
        t = time.time()
        b = subprocess.run(['cargo', 'build', '--release', '--offline', '--locked'], cwd=CRATE)
        if b.returncode: sys.exit('build failed')
        print(f'build {time.time()-t:.0f}s')
    stamp = datetime.datetime.now().strftime('%Y%m%dT%H%M%S')
    outdir = os.path.join(ROOT, 'core', 'results', 'E4', stamp + ('-quick' if a.quick else ''))
    os.makedirs(outdir)
    base = meta(sys.argv)
    n_full, n_weak = (2, 2) if a.quick else (10, 10)
    configs = []
    for d in (8, 16, 32):
        configs.append((f'full_d{d}_tdefault', ['bench', '--variant', 'full', '--depth', str(d), '--runs', str(n_full), '--fresh-params'], {}))
    for d in (8, 16, 32):
        configs.append((f'weak_d{d}_tdefault', ['bench', '--variant', 'weak', '--depth', str(d), '--runs', str(n_weak), '--fresh-params'], {}))
    configs.append(('full_d32_t1', ['bench', '--variant', 'full', '--depth', '32', '--runs', '2' if a.quick else '5'],
                    {'RAYON_NUM_THREADS': '1'}))
    configs.append(('adversarial_full_d32', ['adversarial', '--variant', 'full', '--depth', '32', '--mock'], {}))
    configs.append(('adversarial_weak_d32', ['adversarial', '--variant', 'weak', '--depth', '32', '--mock'], {}))
    only = set(filter(None, a.only.split(',')))
    for name, args, env in configs:
        if only and name not in only:
            continue
        run(outdir, name, args, env, base)
    json.dump(dict(base, finished=datetime.datetime.now().isoformat(timespec='seconds'),
                   load_avg_at_end=os.getloadavg()), open(os.path.join(outdir, 'run_meta.json'), 'w'), indent=2)
    print('results in', outdir)


if __name__ == '__main__':
    main()
