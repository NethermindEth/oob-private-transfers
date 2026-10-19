"""Testbed orchestration: Anvil devnet, contracts, holders, registered providers (all same-host loopback).

All state lives under testbed/<run>/ (or $OOB_TESTBED/<run>/) (destructive tests only there).
"""
from __future__ import annotations

import json
import os
import secrets
import shutil
import signal
import subprocess
import sys
import time
from pathlib import Path

from nacl.signing import SigningKey

from .common import ANVIL, ROOT, TESTBED, Chain, free_port, get_json, post_json

ACCT_DEPLOYER, ACCT_SENDER = 0, 1
# Provider accounts (a provider's own account registers it and writes its directory entry
# and anchors; there is no governance party). A, B, C use fixed indices; other names (e.g. replacements 'A2') get the
# next free index from 11 on (Anvil is started with 40 accounts).
GOV = {'A': 2, 'B': 3, 'C': 4}
OPS = {'A': 5, 'B': 6, 'C': 7}  # unused accounts; negative tests use them as outsiders


class Testbed:
    """n_holders holder processes; register(name, k, q) assigns the first n of them with thresholds (k, n, q).
    seal_mode defaults to $OOB_SEAL_MODE or 'fragment_kzg'. Everything runs on ONE host (one fault domain)."""

    def __init__(self, run: str, block_time: float | None = 1.0, n_holders: int = 5, base: Path = TESTBED,
                 seal_mode: str | None = None, holder_extra: dict | None = None):
        self.seal_mode = seal_mode or os.environ.get('OOB_SEAL_MODE', 'fragment_kzg')
        self.accounts = dict(GOV)
        self.holder_extra = dict(holder_extra or {})
        self.dir = Path(base) / run
        if not self.dir.resolve().is_relative_to(TESTBED) or self.dir.resolve() == TESTBED:
            raise ValueError('destructive work only within a testbed subdirectory')
        self.dir.mkdir(parents=True, exist_ok=False)
        (self.dir / 'configs').mkdir()
        (self.dir / 'logs').mkdir()
        self.procs: dict[str, subprocess.Popen] = {}
        self.port = free_port()
        self.rpc = f'http://127.0.0.1:{self.port}'
        args = [str(ANVIL), '--host', '127.0.0.1', '--port', str(self.port), '--hardfork', 'cancun', '--silent',
                '--accounts', '40', '--gas-limit', '60000000']
        if block_time:
            args += ['--block-time', str(block_time)]
        self.block_time = block_time
        self.spawn('anvil', args)
        for _ in range(100):
            try:
                self.chain = Chain(self.rpc)
                self.chain.tip()
                break
            except Exception:
                time.sleep(0.1)
        t0 = time.perf_counter()
        self.addresses = self.chain.call('deploy')
        self.deploy_s = time.perf_counter() - t0
        self.admin_token = secrets.token_hex(16)
        self.holders = []
        self.gas = {}
        for i in range(n_holders):
            self.start_holder(i, wait=False)
        for h in self.holders:
            self.wait_http(h['name'], h['url'])
        self.services: dict[str, dict] = {}
        self.providers: dict[str, dict] = {}
        self.holder_sets: dict[str, list[int]] = {}  # per service: indices into self.holders (registry order)
        self.thresholds: dict[str, tuple[int, int, int]] = {}  # per service: current (k, n, q)

    # ------------------------------------------------------------------ processes
    def spawn(self, name, cmd, env=None):
        log = open(self.dir / 'logs' / f'{name}.log', 'ab')
        p = subprocess.Popen(cmd, cwd=ROOT, stdout=log, stderr=subprocess.STDOUT, start_new_session=True,
                             env=dict(os.environ, PYTHONPATH=str(ROOT), **(env or {})))
        self.procs[name] = p
        return p

    def kill(self, name, sig=signal.SIGKILL):
        p = self.procs.pop(name, None)
        if p and p.poll() is None:
            try:
                os.killpg(p.pid, sig)
            except ProcessLookupError:
                pass
            try:
                p.wait(timeout=10)
            except subprocess.TimeoutExpired:
                os.killpg(p.pid, signal.SIGKILL)
                p.wait()

    def wait_http(self, name, url, timeout=120):
        t = time.time()
        while time.time() - t < timeout:
            p = self.procs.get(name)
            if p is not None and p.poll() is not None:
                raise RuntimeError(f'{name} exited rc={p.returncode}; see {self.dir}/logs/{name}.log')
            try:
                st, _ = get_json(url + '/status', timeout=2)
                if st == 200:
                    return
            except Exception:
                pass
            time.sleep(0.05)
        raise TimeoutError(name)

    def close(self):
        for name in list(self.procs)[::-1]:
            self.kill(name, signal.SIGTERM if name == 'anvil' else signal.SIGKILL)
        try:
            self.chain.close()
        except Exception:
            pass

    # ------------------------------------------------------------------ holders
    def start_holder(self, i, faults=None, wait=True, port=None, **extra):
        """Start (or restart, same key and data dir) holder i; `port` moves it to a new endpoint."""
        if i < len(self.holders):
            h = self.holders[i]
            if port is not None:
                h['port'], h['url'] = port, f'http://127.0.0.1:{port}'
        else:
            assert i == len(self.holders)
            sk = SigningKey.generate()
            port = port or free_port()
            h = {'name': f'holder{i + 1}', 'i': i + 1, 'sk': sk.encode().hex(), 'key': bytes(sk.verify_key).hex(),
                 'port': port, 'url': f'http://127.0.0.1:{port}', 'data_dir': str(self.dir / f'holder{i + 1}')}
            self.holders.append(h)
        cfg = {'name': h['name'], 'port': h['port'], 'data_dir': h['data_dir'], 'sk': h['sk'], 'rpc': self.rpc,
               'addresses': self.addresses, 'admin_token': self.admin_token, 'faults': faults or {}}
        cfg.update(self.holder_extra)
        cfg.update(extra)
        path = self.dir / 'configs' / f"{h['name']}.json"
        path.write_text(json.dumps(cfg, indent=1))
        self.spawn(h['name'], [sys.executable, '-m', 'core.oobsvc.holder', str(path)])
        if wait:
            self.wait_http(h['name'], h['url'])
        return h

    def move_holder(self, i, port=None):
        """Same identity, key and data, new endpoint : kill and restart on another port."""
        self.kill(self.holders[i]['name'])
        return self.start_holder(i, port=port or free_port())

    def holder_fault(self, i, faults):
        return post_json(self.holders[i]['url'] + '/admin/fault', {'token': self.admin_token, 'faults': faults})

    def holder_list(self, name=None):
        """The holder assignment registered for service `name` (coordinate order)."""
        idx = self.holder_sets.get(name, list(range(len(self.holders) if name is None else 0)))
        return [{'i': c + 1, 'url': self.holders[ix]['url'], 'key': self.holders[ix]['key']} for c, ix in enumerate(idx)]

    def set_assignment(self, name, idx, k=None, q=None):
        """Provider `name` itself installs a new holder assignment gamma (idx = indices into self.holders)."""
        k = k if k is not None else self.thresholds[name][0]
        acct = self.account_of(name)
        q = q if q is not None else (self.thresholds[name][2] if len(idx) == self.thresholds[name][1] else len(idx))
        hs = [self.holders[ix] for ix in idx]
        r = self.chain.call('set_assignment', **{'from': acct}, sid='0x' + self.services[name]['sid'],
                            holder_keys=['0x' + h['key'] for h in hs], holder_urls=[h['url'] for h in hs], k=k, q=q)
        self.holder_sets[name] = list(idx)
        self.thresholds[name] = (k, len(idx), q)
        self.gas[f'set_assignment_{name}'] = int(r['gas'])
        return r

    def set_holders(self, name, idx):
        return self.set_assignment(name, idx)

    def set_holder_endpoint(self, name, ix):
        """Provider `name` updates the endpoint record of holder identity ix (no new assignment)."""
        h = self.holders[ix]
        r = self.chain.call('set_holder_endpoint', **{'from': self.account_of(name)}, sid='0x' + self.services[name]['sid'],
                            holder_key='0x' + h['key'], url=h['url'])
        self.gas[f'set_holder_endpoint_{name}'] = int(r['gas'])
        return r

    # ------------------------------------------------------------------ services
    def account_of(self, name):
        if name not in self.accounts:
            self.accounts[name] = max(10, *self.accounts.values()) + 1
        return self.accounts[name]

    def register(self, name, k=None, q=None, idx=None, continues=None, start_epoch=None):
        """Register provider `name` (its own account; sid = SHA-256 of the account key) with assignment gamma = 0:
        holders idx (default: all started holders) and thresholds (k, n = len(idx), q); default (3, 5, 5) for 5 holders.
        continues = name of a failed provider P that this provider P' replaces: P' declares "continues P" and starts at
        epoch last_P + 1 (last anchored epoch of P at the finalized height), unless start_epoch is given."""
        sk = SigningKey.generate()
        acct = self.account_of(name)
        port = free_port()  # the endpoint is registered on chain, so the port is fixed at registration
        if continues is not None and idx is None and k is None:  # default: the predecessor's current holders and (k, q)
            idx = list(self.holder_sets[continues])
            k, _, q = self.thresholds[continues]
        idx = list(idx) if idx is not None else list(range(len(self.holders)))
        n = len(idx)
        if k is None:
            assert n == 5, 'give k and q explicitly for n != 5'
            k = 3
        q = n if q is None else q
        cont, start = '0x' + '00' * 32, 0
        if continues is not None:
            cont = '0x' + self.services[continues]['sid']
            if start_epoch is None:
                anchored = self.chain.call('list_anchors', sid=cont, height=self.chain.finalized_height())
                start_epoch = (max(anchored) + 1) if anchored else self.services[continues].get('start_epoch', 0)
            start = start_epoch
        hs = [self.holders[ix] for ix in idx]
        r = self.chain.call('register', **{'from': acct}, op_key='0x' + bytes(sk.verify_key).hex(),
                            holder_keys=['0x' + h['key'] for h in hs], holder_urls=[h['url'] for h in hs], k=k, q=q,
                            endpoint=f'http://127.0.0.1:{port}', continues=cont, start_epoch=start)
        self.holder_sets[name] = idx
        self.thresholds[name] = (k, n, q)
        self.chain.wait_final(r['block'])  # readers use the finalized height: wait until the registration is final
        self.gas[f'register_{name}'] = int(r['gas'])
        svc = {'name': name, 'sid': r['sid'][2:], 'operator_sk': sk.encode().hex(), 'op_eoa_index': acct, 'port': port,
               'continues': continues, 'start_epoch': start}
        self.services[name] = svc
        return svc

    def set_endpoint(self, name, url):
        r = self.chain.call('set_endpoint', **{'from': self.account_of(name)}, sid='0x' + self.services[name]['sid'],
                            endpoint=url)
        self.gas[f'set_endpoint_{name}'] = int(r['gas'])
        return r

    def provider_cfg(self, name, data_dir, mode='normal', **extra):
        """mode 'normal', or 'replace': provider `name` (registered with continues=P) starts with EMPTY storage and
        runs Replace(P -> name) before enabling appends."""
        assert mode in ('normal', 'replace'), mode
        svc = self.services[name]
        cfg = {'name': name, 'sid': svc['sid'], 'port': svc['port'], 'data_dir': str(data_dir), 'rpc': self.rpc,
               'addresses': self.addresses, 'admin_token': self.admin_token,
               'M_max': 4096, 'T_max': 10.0, 'mode': mode, 'seal_mode': self.seal_mode,
               'operator_eoa_index': svc['op_eoa_index'], 'operator_sk': svc['operator_sk'],
               'admission': {'depth': 32, 'variant': 'full', 'verifiers': 1}}
        cfg.update(extra)
        return cfg

    def start_provider(self, name, mode='normal', data_dir=None, env=None, wait=True, tag=None, sandbox_deny=None, **extra):
        data_dir = Path(data_dir or self.dir / f'provider-{name}' / 'data')
        cfg = self.provider_cfg(name, data_dir, mode, **extra)
        pname = f'provider-{name}' + (f'-{tag}' if tag else '')
        path = self.dir / 'configs' / f'{pname}.json'
        path.write_text(json.dumps(cfg, indent=1))
        info = {'name': name, 'proc': pname, 'url': f"http://127.0.0.1:{cfg['port']}", 'cfg': cfg, 'cfg_path': str(path)}
        cmd = [sys.executable, '-m', 'core.oobsvc.provider', str(path)]
        if sandbox_deny:
            # A6: macOS sandbox-exec profile denying ANY file access to the destroyed provider dir, the sender's
            # retained copy and fixtures (in addition to the deletion check and the open-files scan).
            prof = '(version 1)\n(allow default)\n' + ''.join(
                f'(deny file-read* file-write* (subpath "{os.path.realpath(d)}"))\n' for d in sandbox_deny)
            (self.dir / 'configs' / f'{pname}.sb').write_text(prof)
            info['sandbox_profile'] = prof
            cmd = ['/usr/bin/sandbox-exec', '-p', prof] + cmd
        self.spawn(pname, cmd, env=env)
        self.providers[name] = info
        if wait:
            self.wait_http(pname, info['url'])
        return info

    def status(self, name):
        return get_json(self.providers[name]['url'] + '/status')[1]

    def admin(self, name, path, **body):
        return post_json(self.providers[name]['url'] + path, dict(body, token=self.admin_token), timeout=600)

    def pdesc(self, name):
        p = self.providers[name]
        return {'name': name, 'sid': self.services[name]['sid'], 'url': p['url']}

    def wait_state(self, name, e, states=('certified',), timeout=300):
        t = time.perf_counter()
        while time.perf_counter() - t < timeout:
            s = self.status(name)
            ep = {x['e']: x for x in s['epochs']}.get(e)
            if ep and ep['state'] in states:
                return time.perf_counter() - t, ep
            time.sleep(0.05)
        raise TimeoutError(f'{name} epoch {e} not in {states}: {ep}')
