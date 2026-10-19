"""A9 (MODELED from measured components): OOB vs "direct delivery + encrypted erasure-coded backup to n independent
stores" (Tahoe-LAFS-style). Inputs: latest E1 raw (append bytes, proof bytes, read bytes) and E6 raw (holder storage).
Output: core/results/E6/e6_a9_model.tex (tabular body) + JSON next to it. Labeled "modeled"."""
import json
import statistics as st
from pathlib import Path

R = Path(__file__).resolve().parents[2] / 'results'


def latest(exp, name):
    fs = sorted((R / exp).glob(f'*/{name}'))
    return json.loads(fs[-1].read_text()) if fs else None


def main():
    e1 = latest('E1', 'e1_raw.json')
    if not e1:
        raise SystemExit('Run E1 before generating this model.')
    runs = [r for r in e1['runs'] if r.get('ok')]
    up = st.median([r['append']['attempts'][0]['bytes_up'] for r in runs])
    rd = runs[0]['read']
    pir_cold = st.median([r['read']['hint_bytes'] + r['read']['public_bytes'] + r['read']['query_bytes'] + r['read']['answer_bytes'] for r in runs])
    pir_warm = st.median([r['warm_read']['query_bytes'] + r['warm_read']['answer_bytes'] for r in runs])
    m_e, rec, k, n = 4096, 736, 3, 5
    frag = rec * n / k
    model = {
        'oob': {'sender_upload_B': up, 'service_storage_B_per_record': None, 'erasure_B_per_record': frag,
                'seal_bandwidth_B_per_record': n * rec, 'recipient_read_B': {'pir_cold': pir_cold, 'pir_warm': pir_warm,
                                                                          'whole_epoch': m_e * rec}},
        'direct_plus_backup': {'sender_upload_B': rec + frag, 'erasure_B_per_record': frag, 'seal_bandwidth_B_per_record': frag,
                               'recipient_read_B': {'direct': rec, 'whole_bucket_private': m_e * rec}},
    }
    rows = [
        f'Sender upload per note & {up / 1e3:.1f}\\,kB (record + proof) & {(rec + frag) / 1e3:.1f}\\,kB (msg + fragments) \\\\',
        f'Backup storage per record & {frag:.0f}\\,B (RS(3,5)) & {frag:.0f}\\,B (RS(3,5)) \\\\',
        f'Sealing/dispersal bandwidth per record & {n * rec}\\,B (full-epoch check) & {frag:.0f}\\,B \\\\',
        f'Recipient private read & {pir_cold / 1e6:.1f}\\,MB cold / {pir_warm / 1e3:.0f}\\,kB warm & {m_e * rec / 1e6:.1f}\\,MB bucket \\\\',
        'One slot per finalized output (anonymous) & yes (tag + proof) & no \\\\',
        'Stored bytes proven = committed note & yes (P1 + A11) & no \\\\',
        'Service survives replacement (locators, $U$) & yes (new provider identity) & no service \\\\',
    ]
    out = R / 'E6'
    out.mkdir(exist_ok=True)
    (out / 'e6_a9_model.tex').write_text('% MODELED from measured E1 components (core/experiments/E6/model_a9.py); not an executed baseline\n'
                                         'Property & OOB (P1) & direct + EC backup (modeled) \\\\ \\hline\n' + '\n'.join(rows) + '\n')
    (out / 'e6_a9_model.json').write_text(json.dumps(model, indent=1))
    print((out / 'e6_a9_model.tex').read_text())


if __name__ == '__main__':
    main()
