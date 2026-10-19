"""Model epoch sizes from an explicit arrival rate and a generated PIR crossover file."""
import argparse
import json
import os
from pathlib import Path

ap = argparse.ArgumentParser()
ap.add_argument('run', help='Directory containing crossover.json from the PIR sweep')
ap.add_argument('--rate', type=float, required=True, help='Assumed record arrivals per second')
args = ap.parse_args()
if args.rate <= 0:
    ap.error('--rate must be positive')
run, rate = args.run, args.rate
output = Path(__file__).resolve().parents[2] / 'results/E5pir'
output.mkdir(parents=True, exist_ok=True)
cx = json.load(open(os.path.join(run, 'crossover.json')))['result']['rows']
mstar = next(r['m_stable'] for r in cx if r['layout'] == 'best' and r['reads'] == 1)
M_MAX = 4096
rows = []
for label, T in [('10 s', 10), ('1 min', 60), ('1 h', 3600), ('1 day', 86400)]:
    for mult, mlabel in [(1, '1x'), (10, '10x')]:
        m = min(M_MAX, rate * mult * T)
        rows.append(dict(T_max=label, rate_multiplier=mlabel, expected_m_e=m, cheaper='PIR' if m >= mstar else 'download'))
out = dict(kind='modeled', rate_outputs_per_s=rate, source='user-supplied arrival-rate assumption', M_max=M_MAX, m_star_best_1read=mstar, rows=rows)
json.dump(out, (output / 'epoch_model.json').open('w'), indent=1)
tex = [f"% MODELED by core/experiments/E5pir/epoch_model.py; rate={rate:.4f}/s (assumed arrival rate), m*={mstar}"]
for r in rows:
    tex.append(f"{r['T_max']} & {r['rate_multiplier']} & {r['expected_m_e']:.1f} & {r['cheaper']} \\\\")
(output / 'epoch_model.tex').open('w').write("\n".join(tex) + "\n")
print(json.dumps(out, indent=1))
