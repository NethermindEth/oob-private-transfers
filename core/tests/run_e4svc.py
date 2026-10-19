"""Run the correctness suites and save JUnit XML + summary JSON to core/results/E4svc/<ts>/.

Library tests (mode-independent or internally parameterized over both seal modes) run once; the service suites
(test_e4_service.py: (k,n,q) = (3,5,5), genuine admission-proved records; test_v2_service.py: (4,8,6)) run once per
seal mode (OOB_SEAL_MODE = fragment_kzg, whole_epoch). Usage: run_e4svc.py [--modes fragment_kzg,whole_epoch] [pytest args]
"""
import json
import os
import subprocess
import sys
import time
import xml.etree.ElementTree as ET

from core.oobsvc.common import CORE, ROOT, metadata

args = sys.argv[1:]
modes = ['fragment_kzg', 'whole_epoch']
if args and args[0].startswith('--modes'):
    modes = (args[0].split('=', 1)[1] if '=' in args[0] else args[1]).split(',')
    args = args[1:] if '=' in args[0] else args[2:]
ts = time.strftime('%Y%m%d-%H%M%S')
out = CORE / 'results/E4svc' / ts
out.mkdir(parents=True)
t0 = time.time()
runs = [('library', None, ['core/tests/test_recovery_units.py', 'core/tests/test_protocol_v2_units.py'])]
runs += [(f'service-{m}', m, ['core/tests/test_e4_service.py', 'core/tests/test_v2_service.py']) for m in modes]
cases, rcs, cmds = [], {}, {}
for name, mode, files in runs:
    cmd = [sys.executable, '-m', 'pytest', '-q', '-p', 'no:cacheprovider', f'--junitxml={out}/junit-{name}.xml', *files, *args]
    env = dict(os.environ, PYTHONPATH=str(ROOT))
    if mode:
        env['OOB_SEAL_MODE'] = mode
    cmds[name] = {'cmd': cmd, 'OOB_SEAL_MODE': mode}
    rcs[name] = subprocess.call(cmd, cwd=ROOT, env=env)
    root = ET.parse(out / f'junit-{name}.xml').getroot()
    for tc in root.iter('testcase'):
        st = ('failed' if tc.find('failure') is not None or tc.find('error') is not None
              else 'skipped' if tc.find('skipped') is not None else 'passed')
        msg = next((x.get('message') for x in tc if x.tag in ('failure', 'error', 'skipped')), None)
        cases.append({'run': name, 'seal_mode': mode, 'name': f"{tc.get('classname')}::{tc.get('name')}", 'status': st,
                      'time_s': float(tc.get('time', 0)), 'message': msg})
rc = max(rcs.values())
summary = {'meta': metadata({'runs': cmds}), 'rc': rc, 'rc_per_run': rcs, 'wall_s': time.time() - t0,
           'counts': {k: sum(c['status'] == k for c in cases) for k in ('passed', 'failed', 'skipped')},
           'counts_per_run': {r: {k: sum(c['status'] == k and c['run'] == r for c in cases) for k in ('passed', 'failed', 'skipped')}
                              for r in rcs},
           'cases': cases,
           'note': 'Implementation-behaviour regressions against real provider/holder processes on ONE host; not proofs of '
                   'ZK/privacy/unforgeability/availability.'}
(out / 'summary.json').write_text(json.dumps(summary, indent=1))
print(json.dumps(summary['counts']), json.dumps(summary['counts_per_run']), out)
sys.exit(rc)
