"""Sender and recipient clients.

Sender: real private transfer on the pool (Groth16 spend proof) -> finality -> message m -> Rust encrypt ->
tag/digest -> Merkle path at the finalized height -> Rust admission proof -> append to r providers (sequential with
per-attempt deadline T_w, or parallel) -> retain rec until its epoch anchor is final -> authenticated notification.
Recipient: wait read-ready -> public params + hint (cold) or reuse (warm) -> SimplePIR query/answer -> digest check ->
receipt check against the registry -> Rust decrypt -> recompute payloadHash/cm/tag -> finalized-leaf check.
"""
from __future__ import annotations

import json
import secrets
import shutil
import time
from concurrent.futures import ThreadPoolExecutor
from dataclasses import dataclass, field
from pathlib import Path

from nacl.signing import SigningKey

from .common import (DENOMINATION, FIELD, H, Chain, b64, canon, d_rec, fe_hex, get_json, http, make_rec, post_json,
                     receipt_message, sign, split_rec, u64, unb64, verify_sig, REC_BYTES)
from .workers import Admission, PirClient


def dec(h: str) -> str:
    return str(int(h, 16))


@dataclass
class Address:
    """Recipient address addr = (ob, pk_R): ob = Poseidon1(secret), pk_R BabyJubjub.
    The note owner field is own = Poseidon2(ob, Poseidon2(pk_R.x, pk_R.y))."""
    pk: list  # [x_hex, y_hex]
    ob: str  # decimal
    owner: str  # decimal owner field (derived)


def make_address(chain: Chain, secret: str, pk: list) -> Address:
    ob = chain.call('hash', values=[secret])
    pkh = chain.call('hash', values=[dec(pk[0]), dec(pk[1])])
    return Address(pk=pk, ob=ob, owner=chain.call('hash', values=[ob, pkh]))


@dataclass
class SpendableNote:
    secret: str
    pk_hash: str
    seed: str
    payload_hash: str
    cm: str  # decimal strings


def registry_key(chain: Chain, sid_hex: str) -> bytes | None:
    """The ONE Ed25519 key registered for provider sid (no rotation in protocol v2)."""
    s = chain.call('service', sid='0x' + sid_hex)
    return bytes.fromhex(s['op_key'][2:]) if int(s['op_key'], 16) else None


def check_receipt(chain, sid_hex, e, j, digest_hex, receipt) -> bool:
    """rho_app = Sign_{sk_P}(OOB-app-v1, sid, e, j, d_rec) under P's registered key."""
    key = registry_key(chain, sid_hex)
    if key is None:
        return False
    return verify_sig(key, receipt_message(bytes.fromhex(sid_hex), e, j, bytes.fromhex(digest_hex)),
                      bytes.fromhex(receipt['sig']))


class Sender:
    def __init__(self, chain: Chain, prover: Admission, account: int, retention_dir: Path, notify_sk: SigningKey | None = None):
        self.chain, self.prover, self.account = chain, prover, account
        self.retention = Path(retention_dir)
        self.retention.mkdir(parents=True, exist_ok=True)
        self.notify_sk = notify_sk or SigningKey.generate()

    # ------------------------------------------------------------- consensus plane
    def deposit_note(self) -> tuple[SpendableNote, dict]:
        secret = str(secrets.randbelow(FIELD - 1) + 1)
        pkh = str(secrets.randbelow(FIELD))  # Poseidon2 of the sender's own encryption key (not needed here)
        seed = str(secrets.randbelow(FIELD))
        ph = str(secrets.randbelow(FIELD))
        ob = self.chain.call('hash', values=[secret])
        owner = self.chain.call('hash', values=[ob, pkh])
        cm = self.chain.call('hash', values=[owner, seed, ph])
        tx = self.chain.call('deposit', cm=cm, **{'from': self.account})
        return SpendableNote(secret, pkh, seed, ph, cm), tx

    def build_message(self, to: Address) -> list[str]:
        m = [to.pk[0], to.pk[1], fe_hex(DENOMINATION), fe_hex(secrets.randbelow(FIELD)), fe_hex(0), fe_hex(int(to.owner))]
        m += [fe_hex(secrets.randbelow(FIELD)) for _ in range(12)]  # memo/padding slots (fixed width)
        return m

    def transfer(self, old: SpendableNote, to: Address) -> dict:
        """Real private transfer: output cm = Poseidon3(owner, seed, PoseidonChain(1001, m))."""
        t = {}
        m = self.build_message(to)
        t0 = time.perf_counter()
        ph = self.prover.payload_hash(m)
        cm = self.prover.commitment(m[5], m[3], ph)
        h = self.chain.finalized_height()
        path = self.chain.call('path', cm=old.cm, height=h)
        nf = self.chain.call('hash', values=[old.secret, old.seed])
        inputs = dict(root=path['root'], nullifier=nf, newCommitment=dec(cm), withdrawTo='0', secret=old.secret,
                      pkHash=old.pk_hash, seed=old.seed, payloadHash=old.payload_hash, newOwner=dec(m[5]), newSeed=dec(m[3]),
                      newPayloadHash=dec(ph), siblings=path['siblings'], directions=path['directions'])
        t1 = time.perf_counter()
        proof = self.chain.call('prove', input=inputs)
        t2 = time.perf_counter()
        tx = self.chain.call('transact', args=proof['args'], **{'from': self.account})
        t3 = time.perf_counter()
        t.update(spend_prep_s=t1 - t0, spend_prove_s=t2 - t1, transact_to_receipt_s=t3 - t2)
        return {'message': m, 'cm': cm, 'payload_hash': ph, 'tx': tx, 'timings': t, 'ob': to.ob}

    # ------------------------------------------------------------- OOB write path
    def prepare(self, message: list[str], cm_hex: str, pk, ob: str) -> dict:
        """After finality: encrypt, tag/digest, finalized path and root, admission proof."""
        t = {}
        t0 = time.perf_counter()
        enc = self.prover.encrypt(pk, message)
        C = enc['ciphertext']
        t1 = time.perf_counter()
        d = self.prover.digest(C)
        nu = self.prover.tag(cm_hex, message[3])
        rec = make_rec(nu, C)
        t2 = time.perf_counter()
        h = self.chain.finalized_height()
        path = self.chain.call('path', cm=dec(cm_hex), height=h)
        root = fe_hex(path['root'])
        t3 = time.perf_counter()
        pub = {'root': root, 'digest': d, 'tag': nu}
        wit = {'message': message, 'ob': fe_hex(ob), 'randomness': enc['randomness'], 'nonce': enc['nonce'], 'ciphertext': C,
               'siblings': [fe_hex(s) for s in path['siblings']], 'directions': [int(x) for x in path['directions']]}
        pr = self.prover.prove(pub, wit)
        t4 = time.perf_counter()
        t.update(encrypt_s=t1 - t0, tag_digest_s=t2 - t1, path_s=t3 - t2, prove_s=t4 - t3,
                 prove_worker_s=pr.get('prove_seconds'))
        (self.retention / f'{nu}.rec').write_bytes(rec)  # retained until the anchor of its epoch is final
        return {'h': h, 'public': pub, 'proof': pr['proof'], 'proof_bytes': pr.get('proof_bytes'), 'rec': rec,
                'nu': nu, 'timings': t, 'witness': wit}  # witness stays client-side (never sent)

    def append_one(self, prov: dict, prep: dict, T_w: float) -> dict:
        body = {'sid': prov['sid'], 'h': prep['h'], 'public': prep['public'], 'proof': prep['proof'], 'rec': b64(prep['rec'])}
        raw = canon(body)
        t0 = time.perf_counter()
        a = {'provider': prov['name'], 'sid': prov['sid'], 'bytes_up': len(raw)}
        try:
            st, data, nbytes = post_json(prov['url'] + '/append', body, timeout=T_w)
            a.update(status=st, bytes_down=nbytes, outcome=data.get('outcome'), error=data.get('error'))
            if st == 200:
                ok = (data['sid'] == prov['sid'] and data['d_rec'] == d_rec(prep['rec']).hex()
                      and check_receipt(self.chain, prov['sid'], data['e'], data['j'], data['d_rec'], data['receipt']))
                if not ok:
                    a.update(outcome='bad_receipt')
                else:
                    a['entry'] = {'name': prov['name'], 'sid': prov['sid'], 'url': prov['url'], 'e': data['e'], 'j': data['j'],
                                  'd_rec': data['d_rec'], 'receipt': data['receipt']}
                    a['server_timings'] = data.get('timings')
        except OSError as exc:  # timeout, refused, reset, dropped connection
            a.update(status=0, outcome='timeout' if 'timed out' in str(exc) else 'transport_error', error=str(exc))
        a['latency_s'] = time.perf_counter() - t0
        return a

    def append(self, providers: list[dict], prep: dict, r: int = 1, policy: str = 'sequential', T_w: float = 30.0) -> dict:
        t0 = time.perf_counter()
        attempts, entries = [], []
        if policy == 'sequential':
            for prov in providers:
                if len(entries) >= r:
                    break
                a = self.append_one(prov, prep, T_w)
                attempts.append(a)
                if 'entry' in a:
                    entries.append(a['entry'])
        elif policy == 'hedged':  # send to ALL listed providers at once; return once r copies are accepted
            from concurrent.futures import as_completed
            ex = ThreadPoolExecutor(len(providers))
            futs = [ex.submit(self.append_one, p, prep, T_w) for p in providers]
            for f in as_completed(futs):
                a = f.result()
                attempts.append(a)
                if 'entry' in a:
                    entries.append(a['entry'])
                if len(entries) >= r:
                    break
            ex.shutdown(wait=False)
            contacted = [p['name'] for p in providers]
        elif policy == 'parallel':
            queue = list(providers)
            while len(entries) < r and queue:
                batch, queue = queue[:r - len(entries)], queue[r - len(entries):]
                with ThreadPoolExecutor(len(batch)) as ex:
                    res = list(ex.map(lambda p: self.append_one(p, prep, T_w), batch))
                attempts += res
                entries += [a['entry'] for a in res if 'entry' in a]
        else:
            raise ValueError(policy)
        return {'policy': policy, 'r': r, 'T_w': T_w, 'attempts': attempts, 'entries': entries,
                'providers_contacted': contacted if policy == 'hedged' else [a['provider'] for a in attempts],
                'accepted': len(entries), 'complete': len(entries) >= r, 'append_total_s': time.perf_counter() - t0}

    def notify(self, inbox: Path, entries: list[dict], cm_hex: str, tx_block: int) -> dict:
        t0 = time.perf_counter()
        body = {'v': 'OOB-notify-v1', 'entries': entries, 'cm': cm_hex, 'tx_block': tx_block}
        msg = canon(body)
        note = {'body': body, 'sender_key': bytes(self.notify_sk.verify_key).hex(),
                'sig': sign(self.notify_sk, b'OOB-notify-v1' + msg).hex()}
        inbox = Path(inbox)
        inbox.mkdir(parents=True, exist_ok=True)
        p = inbox / f'{cm_hex[:16]}-{time.time_ns()}.json'
        raw = json.dumps(note).encode()
        tmp = p.with_suffix('.tmp')
        tmp.write_bytes(raw)
        tmp.rename(p)
        return {'path': str(p), 'bytes': len(raw), 'notify_s': time.perf_counter() - t0}

    def check_durable(self, en: dict, rec: bytes, holders: list[dict] | None = None) -> dict:
        """Release condition for one copy: Certified(sid,e) (q acks, pinned assignment, final anchor) AND the slot
        check passes: a KZG slot opening VerifySlot(com_e, j, rec, sigma)
        (fragment_kzg, I3) or a Merkle path for (j, rec) under R_e (whole_epoch). Openings/paths come from the provider
        or from the epoch's holders (found through the chain); `holders` adds optional extra sources."""
        from .certify import certified
        from .epoch import slot_check
        t0 = time.perf_counter()
        c = certified(self.chain, en['sid'], en['e'])
        if not c['certified']:
            return {'durable': False, 'reason': c['reason']}
        man = c['manifest']
        hs = list(c.get('holders') or []) + list(holders or [])
        if man['mode'] == 'whole_epoch':
            sources = [('provider', lambda: get_json(f"{en['url']}/inclusion/{en['e']}/{en['j']}", timeout=10), 'path')]
            for h in hs:
                sources.append(('holder', lambda h=h: post_json(h['url'] + '/inclusion', {'sid': en['sid'], 'e': en['e'],
                                                                                          'j': en['j']}, timeout=10)[:2], 'path'))
        else:
            sources = [('provider', lambda: get_json(f"{en['url']}/opening/{en['e']}/{en['j']}", timeout=30), 'opening')]
            from .kzg import layout
            if 0 <= en['j'] < man['m_e']:
                t = layout(man['m_e'], man['k']).locate(en['j'])[0]  # only the holder of data coordinate t+1 can open j
                for h in hs:
                    if h.get('i') in (None, t + 1) and h.get('url'):
                        sources.append(('holder', lambda h=h: post_json(h['url'] + '/open', {'sid': en['sid'], 'e': en['e'],
                                                                                             'j': en['j']}, timeout=30)[:2], 'opening'))
        tried = []
        for name, fn, field in sources:
            try:
                st, d = fn()
            except OSError as exc:
                tried.append({'via': name, 'error': str(exc)})
                continue
            if st != 200:
                tried.append({'via': name, 'status': st})
                continue
            ok, why = slot_check(man, en['j'], rec, d.get(field))
            tried.append({'via': name, 'status': st, 'ok': ok, 'why': why})
            if ok:
                return {'durable': True, 'via': name, 'm_e': man['m_e'], 'mode': man['mode'],
                        'tried': tried, 'check_s': time.perf_counter() - t0}
        return {'durable': False, 'reason': 'no valid slot check for (j, rec) under the certified manifest', 'tried': tried}

    def try_release(self, entries: list[dict], rec: bytes, holders=None) -> dict:
        """Delete the retained rec only if EVERY accepted copy is certified with a verified inclusion path."""
        res = [self.check_durable(en, rec, holders) for en in entries]
        ok = bool(res) and all(r['durable'] for r in res)
        if ok:
            f = self.retention / f'{rec[:32].hex()}.rec'
            if f.exists():
                f.unlink()
        return {'released': ok, 'checks': res}


def resolve_endpoint(chain: Chain, sid_hex: str) -> str | None:
    """Resolve the provider endpoint registered at the finalized height."""
    try:
        return chain.call('service', sid='0x' + sid_hex, height=chain.finalized_height()).get('endpoint') or None
    except Exception:
        return None


class ReadFailure(Exception):
    pass


class Recipient:
    def __init__(self, chain: Chain, tool: Admission, sk: str, address: Address, cache_dir: Path, sender_keys: list[str]):
        self.chain, self.tool, self.sk, self.addr = chain, tool, sk, address
        self.cache = Path(cache_dir)
        self.cache.mkdir(parents=True, exist_ok=True)
        self.sender_keys = set(sender_keys)
        self.clients: dict[tuple[str, int], PirClient] = {}

    def resolve(self, en: dict, successors: dict | None = None) -> dict:
        """The endpoint of the provider serving the locator, read from the registry at the finalized height; the notification URL is only a fallback. successors = {sid_P: sid_P'} (harness parameter; how a
        replacement P' is chosen or announced is outside the protocol): the record is then READ at (P', e, j) --
        PIR endpoint, seed and cache use P' -- while its digest and P's receipt are still validated against the
        notified (P, e, j)."""
        rs = (successors or {}).get(en['sid'], en['sid'])
        en = dict(en, read_sid=rs)
        ep = resolve_endpoint(self.chain, rs)
        return dict(en, url=ep, url_source='registry') if ep else dict(en, url_source='notification')

    def load_notification(self, path: Path) -> dict:
        note = json.loads(Path(path).read_text())
        if note['sender_key'] not in self.sender_keys or not verify_sig(
                bytes.fromhex(note['sender_key']), b'OOB-notify-v1' + canon(note['body']), bytes.fromhex(note['sig'])):
            raise ReadFailure('unauthenticated notification')
        return note['body']

    def wait_ready(self, en, T_r, max_wait):
        t0 = time.perf_counter()
        while True:
            st, s = get_json(en['url'] + '/status', timeout=T_r)
            if st != 200:
                raise ReadFailure(f'status {st}')
            ep = {x['e']: x for x in s['epochs']}.get(en['e'])
            if ep and ep['state'] in ('read_ready', 'sealed', 'certified'):
                return time.perf_counter() - t0, ep
            if time.perf_counter() - t0 > max_wait:
                raise ReadFailure('epoch not read-ready before deadline')
            time.sleep(0.02)

    def pir_client(self, en, T_r, m):
        rs = en.get('read_sid', en['sid'])
        key = (rs, en['e'])
        if key in self.clients:
            m['setup'] = 'warm'
            return self.clients[key]
        m['setup'] = 'cold'
        d = self.cache / f"{rs[:16]}-{en['e']}"
        d.mkdir(parents=True, exist_ok=True)
        t0 = time.perf_counter()
        st, pub = http('GET', f"{en['url']}/pir/public/{en['e']}", timeout=T_r)
        if st != 200:
            raise ReadFailure(f'public params refused ({st})')
        st2, hint = http('GET', f"{en['url']}/pir/hint/{en['e']}", timeout=max(T_r, 60))
        if st2 != 200:
            raise ReadFailure(f'hint refused ({st2})')
        t1 = time.perf_counter()
        pj = json.loads(pub)
        expect = H(b'OOB-A', bytes.fromhex(rs), u64(en['e'])).hex()
        if pj.get('seed_A') != expect:
            raise ReadFailure('public params use a seed_A not derived from (sid of the serving provider, e)')
        (d / 'public.json').write_bytes(pub)
        (d / 'hint.bin').write_bytes(hint)
        c = PirClient()
        try:
            r = c.load(d / 'public.json', d / 'hint.bin')
        except Exception as exc:
            c.close()
            raise ReadFailure(f'hint/public load failed: {exc}')
        t2 = time.perf_counter()
        m.update(download_public_hint_s=t1 - t0, public_bytes=len(pub), hint_bytes=len(hint),
                 client_load_s=t2 - t1, client_load_worker=r)
        self.clients[key] = c
        return c

    def validate(self, en, rec, m) -> dict:
        """Authenticated validation (digest vs notification/receipt, receipt vs registry), decryption and note checks."""
        t4 = time.perf_counter()
        if len(rec) != REC_BYTES or d_rec(rec).hex() != en['d_rec']:
            raise ReadFailure('record digest mismatch (tampered or wrong answer)')
        if not check_receipt(self.chain, en['sid'], en['e'], en['j'], en['d_rec'], en['receipt']):
            raise ReadFailure('receipt signature invalid under registry key')
        t5 = time.perf_counter()
        nu, C = split_rec(rec)
        try:
            msg = self.tool.decrypt(self.sk, C)
        except Exception as exc:
            raise ReadFailure(f'decryption failed: {exc}')
        t6 = time.perf_counter()
        if msg[0] != self.addr.pk[0] or msg[1] != self.addr.pk[1] or int(msg[2], 16) != DENOMINATION \
                or int(msg[5], 16) != int(self.addr.owner):
            raise ReadFailure('note fields do not match this recipient address (pk_R, owner field)')
        ph = self.tool.payload_hash(msg)
        cm = self.tool.commitment(msg[5], msg[3], ph)
        if self.tool.tag(cm, msg[3]) != nu:
            raise ReadFailure('admission tag inconsistent with note')
        fin = self.chain.finalized_height()
        if not self.chain.call('member', cm=dec(cm), height=fin):
            raise ReadFailure('cm is not a finalized leaf')
        path = self.chain.call('path', cm=dec(cm), height=fin)
        if not self.chain.call('known_root', root=path['root'], height=fin):
            raise ReadFailure('Merkle path does not reach a finalized root')
        t7 = time.perf_counter()
        m.update(validate_digest_receipt_s=t5 - t4, decrypt_s=t6 - t5, note_check_s=t7 - t6)
        return {'ok': True, 'cm': cm, 'message': msg, 'metrics': m}

    def choose(self, en, T_r, m, policy):
        """A7: whole-epoch download iff m_e*736 <= hint + |q| + |ans| (public sizes)."""
        if policy in ('pir', 'download'):
            m['policy_reason'] = 'forced'
            return policy
        st, s = get_json(en['url'] + '/status', timeout=T_r)
        ep = {x['e']: x for x in s['epochs']}[en['e']]
        mt = ep.get('metrics', {})
        lay = (mt.get('pir_worker') or {}).get('preprocessing', {}).get('layout') or {}
        pir_bytes = mt.get('hint_bytes', 0) + mt.get('public_bytes', 0) + 4 * lay.get('query_len', 0) + 4 * lay.get('l', 0)
        dl = ep['m_e'] * REC_BYTES
        m.update(policy_download_bytes=dl, policy_pir_bytes_est=pir_bytes, anonymity_set=ep['m_e'])
        return 'download' if dl <= pir_bytes else 'pir'

    def read_entry(self, en, T_r=30.0, max_wait=120.0, policy='auto') -> dict:
        m = {'provider': en.get('name'), 'sid': en['sid'], 'read_sid': en.get('read_sid', en['sid']), 'e': en['e']}
        t0 = time.perf_counter()
        m['epoch_wait_s'], ep = self.wait_ready(en, T_r, max_wait)
        m['m_e'] = ep['m_e']
        path = self.choose(en, T_r, m, policy)
        m['read_path'] = path
        t1 = time.perf_counter()
        m['choose_s'] = t1 - t0 - m['epoch_wait_s']
        if path == 'download':
            st, data = http('GET', f"{en['url']}/epoch/{en['e']}", timeout=max(T_r, 60))
            t3 = time.perf_counter()
            if st != 200:
                raise ReadFailure(f'epoch download refused ({st})')
            if len(data) != ep['m_e'] * REC_BYTES or en['j'] >= ep['m_e']:
                raise ReadFailure('epoch download has wrong length')
            rec = data[en['j'] * REC_BYTES:(en['j'] + 1) * REC_BYTES]
            m.update(download_s=t3 - t1, download_bytes=len(data), setup='none')
        else:
            c = self.pir_client(en, T_r, m)
            t1 = time.perf_counter()
            q, state, qr = c.query(en['j'])
            t2 = time.perf_counter()
            st, ans = http('POST', f"{en['url']}/pir/answer/{en.get('read_sid', en['sid'])}/{en['e']}", q,
                           'application/octet-stream', timeout=T_r)
            t3 = time.perf_counter()
            if st != 200:
                raise ReadFailure(f'answer refused ({st})')
            try:
                rec, rr = c.recover(state, ans)
            except Exception as exc:
                raise ReadFailure(f'PIR decode failed: {exc}')
            t4 = time.perf_counter()
            m.update(query_s=t2 - t1, answer_rtt_s=t3 - t2, recover_s=t4 - t3, query_bytes=len(q), answer_bytes=len(ans))
        r = self.validate(en, rec, m)
        m['read_total_s'] = time.perf_counter() - t0
        return r

    def recover_read(self, en, T_r=30.0) -> dict:
        """A3 recipient-side recovery: chain + registry-listed holders, whole-epoch decode, own slot."""
        from .recovery import recipient_recover
        t0 = time.perf_counter()
        recs, m = recipient_recover(self.chain, en['sid'], en['e'], timeout=T_r)
        m['read_path'] = 'recipient_recovery'
        if recs is None:
            raise ReadFailure(f"recipient-side recovery failed: {m.get('reason')}")
        if en['j'] >= len(recs):
            raise ReadFailure('slot outside recovered epoch')
        m['recover_total_s'] = time.perf_counter() - t0
        r = self.validate(en, recs[en['j']], m)
        m['read_total_s'] = time.perf_counter() - t0
        return r

    def receive(self, notification: dict, T_r=30.0, max_wait=120.0, policy='auto', recovery=False,
                successors: dict | None = None) -> dict:
        """Try notified locators in order; never retry the same provider for that epoch; failover to the next;
        optionally fall back to recipient-side recovery of a certified epoch (A3)."""
        attempts = []
        t0 = time.perf_counter()
        notification = dict(notification, entries=[self.resolve(en, successors) for en in notification['entries']])
        for en in notification['entries']:
            ta = time.perf_counter()
            try:
                r = self.read_entry(en, T_r, max_wait, policy)
                attempts.append({'provider': en.get('name'), 'ok': True, 'latency_s': time.perf_counter() - ta,
                                 'url': en['url'], 'url_source': en.get('url_source'), 'metrics': r['metrics']})
                return {'ok': True, 'cm': r['cm'], 'attempts': attempts, 'receive_total_s': time.perf_counter() - t0,
                        'metrics': r['metrics'], 'via': 'provider'}
            except (ReadFailure, OSError, KeyError, ValueError) as exc:
                attempts.append({'provider': en.get('name'), 'ok': False, 'error': f'{type(exc).__name__}: {exc}',
                                 'url': en.get('url'), 'url_source': en.get('url_source'), 'latency_s': time.perf_counter() - ta})
                c = self.clients.pop((en.get('read_sid', en['sid']), en['e']), None)
                if c:
                    c.close()
        if recovery:
            for en in notification['entries']:
                ta = time.perf_counter()
                try:
                    r = self.recover_read(en, T_r)
                    attempts.append({'provider': en.get('name'), 'path': 'recipient_recovery', 'ok': True,
                                     'latency_s': time.perf_counter() - ta, 'metrics': r['metrics']})
                    return {'ok': True, 'cm': r['cm'], 'attempts': attempts, 'receive_total_s': time.perf_counter() - t0,
                            'metrics': r['metrics'], 'via': 'recipient_recovery'}
                except (ReadFailure, OSError, KeyError, ValueError) as exc:
                    attempts.append({'provider': en.get('name'), 'path': 'recipient_recovery', 'ok': False,
                                     'error': f'{type(exc).__name__}: {exc}', 'latency_s': time.perf_counter() - ta})
        return {'ok': False, 'attempts': attempts, 'receive_total_s': time.perf_counter() - t0}

    def close(self):
        for c in self.clients.values():
            c.close()
        self.clients.clear()
