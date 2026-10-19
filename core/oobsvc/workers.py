"""Thin clients for the Rust admission worker (oob-admission) and the Go PIR worker (oob-pir).

Field elements are lowercase 32-byte big-endian hex, no 0x.
"""
from __future__ import annotations

import os
import subprocess
from pathlib import Path

from .common import CORE, HALO_BIN, PIR_BIN, Worker, b64, unb64

from core.paths import HALO_KEYS


class Admission:
    """Rust worker. role in {prover, verifier, tool}; depth 8/16/32; variant full (P1) or weak (W1, E4 only)."""

    def __init__(self, role: str, depth: int = 32, variant: str = 'full', keys: Path | None = None, binary: Path = HALO_BIN):
        keys = Path(keys or os.environ.get('OOB_HALO_KEYS', HALO_KEYS))
        keys.mkdir(parents=True, exist_ok=True)
        self.role, self.depth, self.variant = role, depth, variant
        self.w = Worker([binary, '--keys', keys, '--depth', str(depth), '--variant', variant, '--role', role],
                        stderr=subprocess.DEVNULL)

    @property
    def pid(self):
        return self.w.pid

    def info(self):
        return self.w.call('info')

    def keypair(self):
        r = self.w.call('keypair')
        return r['sk'], r['pk']

    def payload_hash(self, message):
        return self.w.call('payload_hash', message=message)['payload_hash']

    def commitment(self, owner, seed, payload_hash):
        return self.w.call('commitment', owner=owner, seed=seed, payload_hash=payload_hash)['cm']

    def tag(self, cm, seed):
        return self.w.call('tag', cm=cm, seed=seed)['nu']

    def digest(self, ciphertext):
        return self.w.call('digest', ciphertext=ciphertext)['d']

    def encrypt(self, pk, message):
        return self.w.call('encrypt', pk=pk, message=message)

    def decrypt(self, sk, ciphertext):
        return self.w.call('decrypt', sk=sk, ciphertext=ciphertext)['message']

    def prove(self, public, witness):
        return self.w.call('prove', public=public, witness=witness)

    def verify(self, public, proof) -> dict:
        return self.w.call('verify', public=public, proof=proof)

    def close(self):
        self.w.close()


class PirServer:
    """Go worker holding the server DB of ONE epoch (one worker process per read-ready epoch)."""

    def __init__(self, binary: Path = PIR_BIN):
        self.w = Worker([binary], stderr=subprocess.DEVNULL)
        self.epoch_id = None

    @property
    def pid(self):
        return self.w.pid

    def setup(self, records_file: Path, count: int, seed_A: bytes, out_dir: Path, epoch_id: str):
        self.epoch_id = epoch_id
        return self.w.call('setup', records_file=str(records_file), count=count, width=736, seed_A=seed_A.hex(),
                           out_dir=str(out_dir), epoch_id=epoch_id)

    def answer(self, query: bytes) -> tuple[bytes, float]:
        r = self.w.call('answer', epoch_id=self.epoch_id, query=b64(query))
        return unb64(r['answer']), r.get('answer_seconds')

    def close(self):
        self.w.close()


class PirClient:
    """Client-side Go worker for one epoch: load(public, hint) once (cold) then query/recover (warm reuse)."""

    def __init__(self, binary: Path = PIR_BIN):
        self.w = Worker([binary], stderr=subprocess.DEVNULL)

    @property
    def pid(self):
        return self.w.pid

    def load(self, public_json: Path, hint_file: Path):
        return self.w.call('load', public_json=str(public_json), hint_file=str(hint_file))

    def query(self, index: int):
        r = self.w.call('query', index=index)
        return unb64(r['query']), r['state_id'], r
    def recover(self, state_id, answer: bytes):
        r = self.w.call('recover', state_id=state_id, answer=b64(answer))
        return unb64(r['record']), r

    def close(self):
        self.w.close()
