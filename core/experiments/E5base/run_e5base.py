"""Direct delivery baseline and optional compact-scanning comparison.

The compact comparison requires an explicitly supplied external dataset. The direct delivery
measurement uses authenticated local files on the same host, not a network transport.
"""
from __future__ import annotations

import sys
from pathlib import Path
sys.path.insert(0, str(Path(__file__).resolve().parents[3]))
import argparse
import json
import statistics
import time
from pathlib import Path

from nacl.signing import SigningKey

from core.paths import TESTBED
from core.oobsvc.common import CORE, ROOT, canon, metadata, sign, verify_sig


def direct_delivery(trials=200):
    sk = SigningKey.generate()
    d = TESTBED / f'E5base-direct-{time.strftime("%H%M%S")}'
    d.mkdir(parents=True)
    import os
    lat, sizes = [], []
    for i in range(trials):
        rec = os.urandom(736)
        t0 = time.perf_counter()
        body = {'v': 'OOB-direct-v1', 'rec': rec.hex()}
        note = {'body': body, 'sig': sign(sk, b'OOB-direct-v1' + canon(body)).hex()}
        raw = json.dumps(note).encode()
        p = d / f'{i}.json'
        p.write_bytes(raw)
        got = json.loads(p.read_bytes())
        assert verify_sig(bytes(sk.verify_key), b'OOB-direct-v1' + canon(got['body']), bytes.fromhex(got['sig']))
        assert bytes.fromhex(got['body']['rec']) == rec
        lat.append(time.perf_counter() - t0)
        sizes.append(len(raw))
    return {'trials': trials, 'message_bytes': statistics.median(sizes), 'record_bytes': 736,
            'latency_median_s': statistics.median(lat), 'latency_max_s': max(lat),
            'assumptions': 'recipient mailbox reachable and retaining; sender online until delivery; no provider-independent '
                           'recovery, no admission/dedup, no certification; same-host local file (not a network path)'}


def compact(e1, src, normal_outputs_day):
    z = json.loads(src.read_text())
    cs = z['compact_sample']
    bpo = cs['compact_bytes'] / cs['outputs']
    high = z['high_load_30d']['outputs_per_day']
    # OOB (measured in E1, one 2^12 epoch): per private read bytes
    oob = None
    if e1:
        runs = [r for r in e1['runs'] if r.get('ok')]
        rd = [r['read'] for r in runs]
        pir_cold = statistics.median([x['public_bytes'] + x['hint_bytes'] + x['query_bytes'] + x['answer_bytes'] for x in rd])
        pir_warm = statistics.median([r['warm_read']['query_bytes'] + r['warm_read']['answer_bytes'] for r in runs])
        dl = statistics.median([r['auto_read'].get('download_bytes', 0) for r in runs])
        oob = {'pir_cold_bytes_per_read': pir_cold, 'pir_warm_bytes_per_read': pir_warm, 'whole_epoch_download_bytes': dl,
               'epoch_records': 4096, 'source': 'core/results/E1 latest raw'}
    return {'source': str(src), 'retrieved_at': z['retrieved_at'], 'endpoint': z['endpoint'],
            'sample_blocks': cs['blocks'], 'sample_outputs': cs['outputs'], 'compact_bytes_per_output': bpo,
            'bytes_per_day_normal': bpo * normal_outputs_day, 'bytes_per_day_high_2022': bpo * high,
            'outputs_per_day_normal': normal_outputs_day, 'outputs_per_day_high_2022': high,
            'oob_measured': oob,
            'semantics': 'compact scanning discovers notes without locators by trial-decrypting every output (per-output '
                         'ECDH, compute not measured here); OOB notified mode needs a delivered locator and fetches one '
                         'record per owned note; payloads differ (Zcash compact output = cmu+epk+52 B ciphertext prefix)'}


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument('--compact-data', type=Path, help='JSON dataset with compact_sample and high_load_30d statistics')
    ap.add_argument('--normal-outputs-day', type=float, help='Normal-load outputs/day for the compact model')
    args = ap.parse_args()
    if args.compact_data and (args.normal_outputs_day is None or args.normal_outputs_day <= 0):
        ap.error('--compact-data requires a positive --normal-outputs-day')
    ts = time.strftime('%Y%m%d-%H%M%S')
    out = CORE / 'results/E5base' / ts
    out.mkdir(parents=True)
    e1s = sorted((CORE / 'results/E1').glob('*/e1_raw.json'))
    e1 = json.loads(e1s[-1].read_text()) if e1s else None
    raw = {'meta': metadata({'e1_source': str(e1s[-1]) if e1s else None}), 'direct_delivery': direct_delivery(),
           'compact_scanning': compact(e1, args.compact_data, args.normal_outputs_day) if args.compact_data else
           {'status': 'not_run', 'reason': 'No external compact-block dataset supplied'}}
    (out / 'e5base_raw.json').write_text(json.dumps(raw, indent=1))
    print(json.dumps({k: raw[k] for k in ('direct_delivery',)}, indent=1))
    print('wrote', out)


if __name__ == '__main__':
    main()
