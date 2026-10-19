#!/usr/bin/env python3
"""Drive oob-admission over its JSON-lines interface: keypair -> encrypt -> statement -> prove -> verify
-> decrypt, plus a few negative verify calls. Usage: worker_roundtrip.py [--depth 32] [--variant full] [--keys DIR]"""
import sys
from pathlib import Path
sys.path.insert(0, str(Path(__file__).resolve().parents[3]))
from core.paths import HALO_KEYS
import argparse, json, os, secrets, subprocess, sys, time
HERE = os.path.dirname(os.path.abspath(__file__))
BIN = os.path.join(HERE, '..', '..', 'halo2', 'target', 'release', 'oob-admission')
P = 21888242871839275222246405745257275088548364400416034343698204186575808495617

def fe(x): return format(x % P, '064x')

class Worker:
    def __init__(self, args):
        self.p = subprocess.Popen([BIN] + args, stdin=subprocess.PIPE, stdout=subprocess.PIPE, text=True)
    def call(self, **req):
        self.p.stdin.write(json.dumps(req) + '\n'); self.p.stdin.flush()
        r = json.loads(self.p.stdout.readline())
        return r
    def ok(self, **req):
        r = self.call(**req)
        if 'error' in r: raise RuntimeError(f"{req['op']}: {r['error']}")
        return r['result']

def main():
    ap = argparse.ArgumentParser()
    ap.add_argument('--depth', type=int, default=32); ap.add_argument('--variant', default='full')
    ap.add_argument('--keys', default=str(HALO_KEYS))
    a = ap.parse_args()
    t0 = time.time()
    w = Worker(['--keys', a.keys, '--depth', str(a.depth), '--variant', a.variant, '--role', 'prover'])
    info = w.ok(op='info'); print('info', json.dumps(info)); print('startup_s', round(time.time() - t0, 2))
    kp = w.ok(op='keypair')
    ob = fe(secrets.randbelow(P))  # address component ob = Poseidon1(secret) (A11); random stand-in value here
    owner = w.ok(op='owner', ob=ob, pk=kp['pk'])['owner']
    msg = kp['pk'] + [fe(10**16), fe(secrets.randbelow(P)), fe(7), owner] + [fe(i) for i in range(12)]
    enc = w.ok(op='encrypt', pk=kp['pk'], message=msg)
    sib = [fe(secrets.randbelow(P)) for _ in range(a.depth)]; dirs = [secrets.randbelow(2) for _ in range(a.depth)]
    st = w.ok(op='statement', message=msg, ciphertext=enc['ciphertext'], siblings=sib, directions=dirs)
    public = {k: st[k] for k in ('root', 'digest', 'tag')}
    assert w.ok(op='digest', ciphertext=enc['ciphertext'])['d'] == st['digest']
    pr = w.ok(op='prove', public=public, witness=dict(message=msg, ob=ob, randomness=enc['randomness'], nonce=enc['nonce'],
                                                        ciphertext=enc['ciphertext'], siblings=sib, directions=dirs))
    print('prove_s', pr['prove_seconds'], 'proof_bytes', pr['proof_bytes'])
    v = w.ok(op='verify', public=public, proof=pr['proof']); print('verify', v); assert v['valid']
    bad = dict(public, tag=fe(int(public['tag'], 16) + 1))
    assert not w.ok(op='verify', public=bad, proof=pr['proof'])['valid']
    assert not w.ok(op='verify', public=public, proof=pr['proof'][:-2])['valid']
    assert not w.ok(op='verify', public=public, proof='zz')['valid']
    dec = w.ok(op='decrypt', sk=kp['sk'], ciphertext=enc['ciphertext']); assert dec['message'] == msg
    other = w.ok(op='keypair')
    assert w.call(op='decrypt', sk=other['sk'], ciphertext=enc['ciphertext']).get('error') == 'auth'
    # A11: same note with a wrong ob must be refused by the checked prover
    r = w.call(op='prove', public=public, witness=dict(message=msg, ob=fe(1), randomness=enc['randomness'], nonce=enc['nonce'],
                                                        ciphertext=enc['ciphertext'], siblings=sib, directions=dirs))
    if a.variant == 'full': assert 'error' in r and 'A11' in r['error'], r
    print('ROUNDTRIP OK', a.variant, a.depth, 'total_s', round(time.time() - t0, 2))

if __name__ == '__main__':
    main()
