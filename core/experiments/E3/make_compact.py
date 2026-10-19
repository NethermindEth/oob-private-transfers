"""Compact E3 table for the paper: column subset of make_table.py's output (drops 'max' and 'note');
deterministic transform of the script-generated table, no numbers typed. -> core/results/E3/e3_matrix_compact.tex"""
import os
here = os.path.dirname(os.path.abspath(__file__)); res = os.path.join(here, '..', '..', 'results', 'E3')
src = open(os.path.join(res, 'e3_matrix.tex')).read().splitlines()
out = [src[0].replace('make_table.py', 'make_table.py (compacted by make_compact.py)')]
for line in src[2:]:
    if not line.strip().endswith('\\\\'):
        continue
    c = [x.strip() for x in line.rstrip('\\ ').split('&')]
    # Scenario, trials, completed, median, max, attempts, extra alloc, note
    out.append(' & '.join([c[0], c[1], c[2], c[3], c[6]]) + ' \\\\')
open(os.path.join(res, 'e3_matrix_compact.tex'), 'w').write('\n'.join(out) + '\n'); print('\n'.join(out))
