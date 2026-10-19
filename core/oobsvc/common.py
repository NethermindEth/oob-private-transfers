"""Shared helpers: paths, JSON-lines workers, chain wrapper, encodings, hashing, signatures, result metadata."""
from __future__ import annotations

import base64
import hashlib
import json
import os
import platform
import socket
import subprocess
import sys
import threading
import time
import urllib.error
import urllib.request
from pathlib import Path

from nacl.exceptions import BadSignatureError
from nacl.signing import SigningKey, VerifyKey

CORE = Path(__file__).resolve().parents[1]
ROOT = CORE.parent
CONTRACTS = CORE / 'contracts'
HALO_BIN = CORE / 'halo2/target/release/oob-admission'
PIR_BIN = CORE / 'simplepir/oob-pir'
from core.paths import ANVIL, BENCHLOCK, TESTBED

FIELD = 21888242871839275222246405745257275088548364400416034343698204186575808495617
DENOMINATION = 10 ** 16
N_MSG = 18
N_CT = 22
FE = 32
REC_BYTES = FE + N_CT * FE  # 736
# (k, n, q) are per holder assignment (registry) since protocol v2; see epoch.check_thresholds.

b64 = lambda x: base64.b64encode(x).decode()
unb64 = base64.b64decode


def fe_hex(x: int | str) -> str:
    x = int(x)
    assert 0 <= x < FIELD, 'non-canonical field element'
    return x.to_bytes(32, 'big').hex()


def fe_int(h: str) -> int:
    return int(h, 16)


def H(*parts: bytes) -> bytes:
    return hashlib.sha256(b''.join(parts)).digest()


def lp(*parts: bytes) -> bytes:
    """Length-prefixed concatenation (8-byte big-endian lengths) for signed messages."""
    return b''.join(len(p).to_bytes(8, 'big') + p for p in parts)


def u64(x: int) -> bytes:
    return int(x).to_bytes(8, 'big')


def canon(obj) -> bytes:
    return json.dumps(obj, sort_keys=True, separators=(',', ':')).encode()


def d_rec(rec: bytes) -> bytes:
    return H(b'OOB-rec-v1', rec)


def receipt_message(sid: bytes, e: int, j: int, digest: bytes) -> bytes:
    return lp(b'OOB-app-v1', sid, u64(e), u64(j), digest)


def ack_message(h_manifest: bytes, i: int) -> bytes:
    return lp(b'OOB-ack-v1', h_manifest, u64(i))


def sign(sk: SigningKey, msg: bytes) -> bytes:
    return sk.sign(msg).signature


def verify_sig(vk: bytes, msg: bytes, sig: bytes) -> bool:
    try:
        VerifyKey(vk).verify(msg, sig)
        return True
    except (BadSignatureError, ValueError, TypeError):
        return False


def split_rec(rec: bytes) -> tuple[str, list[str]]:
    assert len(rec) == REC_BYTES
    return rec[:32].hex(), [rec[32 + 32 * i:64 + 32 * i].hex() for i in range(N_CT)]


def make_rec(nu_hex: str, ct_hex: list[str]) -> bytes:
    assert len(ct_hex) == N_CT
    return bytes.fromhex(nu_hex) + b''.join(bytes.fromhex(c) for c in ct_hex)


def free_port() -> int:
    with socket.socket() as s:
        s.bind(('127.0.0.1', 0))
        return s.getsockname()[1]


class WorkerError(Exception):
    pass


class Worker:
    """JSON-lines subprocess worker: one request per line, {"result":..} or {"error":..}."""

    def __init__(self, command, env=None, cwd=None, stderr=None):
        self.command = [str(c) for c in command]
        self.proc = subprocess.Popen(self.command, stdin=subprocess.PIPE, stdout=subprocess.PIPE,
                                     stderr=stderr if stderr is not None else subprocess.DEVNULL,
                                     text=True, bufsize=1, env=env, cwd=cwd)
        self.lock = threading.Lock()

    @property
    def pid(self):
        return self.proc.pid

    def call(self, op, **args):
        with self.lock:
            if self.proc.poll() is not None:
                raise WorkerError(f'worker exited rc={self.proc.returncode}: {self.command[0]}')
            self.proc.stdin.write(json.dumps(dict(op=op, **args), separators=(',', ':')) + '\n')
            self.proc.stdin.flush()
            line = self.proc.stdout.readline()
            if not line:
                raise WorkerError(f'worker exited: {self.proc.poll()} ({self.command[0]})')
            reply = json.loads(line)
            if 'error' in reply:
                raise WorkerError(str(reply['error']))
            return reply['result']

    def close(self):
        if self.proc.poll() is None:
            try:
                self.proc.stdin.close()
                self.proc.wait(timeout=5)
            except Exception:
                self.proc.kill()
                self.proc.wait(timeout=5)


class Chain(Worker):
    def __init__(self, rpc: str, addresses: dict | None = None):
        super().__init__(['node', CONTRACTS / 'chain.mjs'], env=dict(os.environ, OOB_RPC=rpc),
                         stderr=subprocess.DEVNULL)
        self.rpc = rpc
        if addresses:
            self.call('attach', addresses=addresses)

    def tip(self) -> int:
        return int(self.call('tip'))

    def finalized_height(self) -> int:
        """Devnet finality rule: height h is final iff >= 1 successor block exists (c = 1)."""
        return self.tip() - 1

    def is_final(self, h: int) -> bool:
        return type(h) is int and 0 <= h <= self.finalized_height()

    def wait_final(self, h: int, timeout: float = 120.0, poll: float = 0.05) -> float:
        t = time.perf_counter()
        while not self.is_final(h):
            if time.perf_counter() - t > timeout:
                raise TimeoutError(f'height {h} not final')
            time.sleep(poll)
        return time.perf_counter() - t


def http(method: str, url: str, body: bytes | None = None, ctype='application/json', timeout: float = 60.0):
    """Returns (status, bytes). Raises OSError subclasses on transport failures/timeouts."""
    req = urllib.request.Request(url, data=body, method=method, headers={'Content-Type': ctype} if body is not None else {})
    opener = urllib.request.build_opener(urllib.request.ProxyHandler({}))
    try:
        with opener.open(req, timeout=timeout) as resp:
            return resp.status, resp.read()
    except urllib.error.HTTPError as exc:
        return exc.code, exc.read()


def post_json(url, obj, timeout=60.0):
    status, raw = http('POST', url, canon(obj), timeout=timeout)
    try:
        data = json.loads(raw)
    except Exception:
        data = {'error': f'non-JSON response ({len(raw)} B)'}
    return status, data, len(raw)


def get_json(url, timeout=30.0):
    status, raw = http('GET', url, timeout=timeout)
    return status, json.loads(raw)


def git_info() -> dict:
    try:
        commit = subprocess.check_output(['git', 'rev-parse', 'HEAD'], cwd=ROOT, text=True, stderr=subprocess.DEVNULL).strip()
        # results written by earlier experiments of the same run are not code changes
        dirty = bool(subprocess.check_output(['git', 'status', '--porcelain', '--', 'core', ':(exclude)core/results'], cwd=ROOT,
                                             text=True).strip())
    except Exception:
        commit, dirty = 'unknown', True
    return {'commit': commit, 'dirty': dirty}


def sh(*cmd) -> str:
    try:
        return subprocess.check_output(cmd, text=True, stderr=subprocess.DEVNULL).strip()
    except Exception:
        return 'unknown'


def metadata(config: dict, seeds: dict | None = None) -> dict:
    import nacl
    import zfec
    return {
        'git': git_info(), 'command': sys.argv, 'config': config, 'seeds': seeds or {},
        'hardware': {'cpu': sh('sysctl', '-n', 'machdep.cpu.brand_string'), 'ncpu': os.cpu_count(),
                     'mem_bytes': int(sh('sysctl', '-n', 'hw.memsize') or 0) if sh('sysctl', '-n', 'hw.memsize').isdigit() else None,
                     'os': sh('sw_vers', '-productVersion'), 'build': sh('sw_vers', '-buildVersion'), 'machine': platform.machine()},
        'load_average_start': os.getloadavg(),
        'versions': {'python': sys.version.split()[0], 'pynacl': nacl.__version__, 'zfec': getattr(zfec, '__version__', '?'),
                     'node': sh('node', '--version'), 'anvil': sh(str(ANVIL), '--version').splitlines()[0] if ANVIL.exists() else None,
                     'halo2_bin_sha256': file_sha(HALO_BIN), 'pir_bin_sha256': file_sha(PIR_BIN),
                     'kzg': _kzg_versions(),
                     'spend_setup': json.loads((CONTRACTS / 'build/setup_info.json').read_text()) if (CONTRACTS / 'build/setup_info.json').exists() else None},
        'network': 'same-host loopback (127.0.0.1); all services on one machine',
        'started_at': time.strftime('%Y-%m-%dT%H:%M:%S%z'),
    }


def _kzg_versions():
    try:
        from .kzg import versions
        return versions()
    except Exception as exc:
        return {'error': str(exc)}


def file_sha(p: Path):
    try:
        return hashlib.sha256(Path(p).read_bytes()).hexdigest()
    except OSError:
        return None


def require_real_binaries():
    """Measured harnesses refuse to run without the real Rust and Go workers."""
    missing = [str(p) for p in (HALO_BIN, PIR_BIN) if not os.access(p, os.X_OK)]
    if missing:
        raise SystemExit(f'refusing to run a measured experiment: real workers missing: {missing}')


def peak_rss(pid: int) -> int | None:
    """Current RSS of a live process (bytes). Peak is tracked by callers sampling this."""
    try:
        import psutil
        return psutil.Process(pid).memory_info().rss
    except Exception:
        return None


class RSSSampler(threading.Thread):
    """Samples RSS of a set of pids every `interval` s; records per-name maxima."""

    def __init__(self, pids: dict[str, int], interval=0.05):
        super().__init__(daemon=True)
        self.pids = dict(pids)
        self.peak = {k: 0 for k in pids}
        self.interval = interval
        self._stop_event = threading.Event()

    def add(self, name, pid):
        self.pids[name] = pid
        self.peak.setdefault(name, 0)

    def run(self):
        import psutil
        procs = {}
        while not self._stop_event.is_set():
            for name, pid in list(self.pids.items()):
                try:
                    p = procs.get(pid) or procs.setdefault(pid, psutil.Process(pid))
                    rss = p.memory_info().rss
                    for c in p.children(recursive=True):
                        try:
                            rss += c.memory_info().rss
                        except Exception:
                            pass
                    self.peak[name] = max(self.peak[name], rss)
                except Exception:
                    pass
            time.sleep(self.interval)

    def stop(self):
        self._stop_event.set()
        self.join(timeout=2)
        return dict(self.peak)


def wait_quiet(max_load: float = 8.0, timeout: float = 900.0) -> dict:
    """Wait until the 1-min load average is <= max_load before timing."""
    t0 = time.time()
    while os.getloadavg()[0] > max_load and time.time() - t0 < timeout:
        time.sleep(5)
    return {'waited_s': time.time() - t0, 'load_at_start': os.getloadavg(), 'max_load_rule': max_load}


def finish_load(meta: dict, contaminated_above: float = 12.0) -> None:
    la = os.getloadavg()
    meta['load_average_end'] = la
    meta['contaminated'] = la[0] > contaminated_above
    meta['contamination_rule'] = f'end 1-min load > {contaminated_above} => contaminated (kept, excluded from tables)'
