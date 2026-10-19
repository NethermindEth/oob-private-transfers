"""Certified(sid, e) and recovery discovery (protocol v2).

Certified(sid, e) at a finalized height h iff: the anchor of (sid, e) is in contract state at h; the manifest and
certificate bytes (from the anchoring event, or from any holder when event logs are unavailable) hash to
the values in contract state; the manifest is signed by P's registered key (the one active at the anchor block) and pins
the holder assignment gamma active at that block (hence k, n, q and every coordinate's identity); the certificate
has q valid acknowledgments at distinct coordinates of gamma. Otherwise the anchor is VOID. There is no retention
expiry: Certified has no end time. Holder endpoints are resolved per identity at the reading height , so
an endpoint move does not change which identity certified an epoch.
"""
from __future__ import annotations

import json
from concurrent.futures import ThreadPoolExecutor

from .common import Chain, canon, post_json
from .epoch import RecoveryError, assignment_of, cert_hash, manifest_hash, verify_cert, verify_manifest


def _strip(x: str) -> str:
    return x[2:] if x.startswith('0x') else x


def registry_at(chain: Chain, sid_hex: str, height: int | None) -> dict:
    s = chain.call('service', sid='0x' + sid_hex, height=height)
    if int(s['governance'], 16) == 0:
        raise RecoveryError('sid not registered')
    s['ops'] = [bytes.fromhex(_strip(k['key'])) for k in s['key_history']]
    s['holder_endpoints'] = {_strip(k): u for k, u in s['holder_endpoints'].items()}
    for a in s['assignments']:
        a['keys'] = [_strip(k) for k in a['keys']]
    s['holders'] = [bytes.fromhex(_strip(k)) for k in s['holder_keys']]
    return s


def current_assignment(reg: dict) -> dict:
    if not reg['assignments']:
        raise RecoveryError('no holder assignment')
    return reg['assignments'][-1]


def assignment_at(reg: dict, block: int) -> dict:
    """Assignment gamma active at `block` (the latest one installed at or before it)."""
    cur = None
    for a in reg['assignments']:
        if a['from_block'] <= block:
            cur = a
    if cur is None:
        raise RecoveryError('no holder assignment active at anchor block')
    return cur


def resolve_holders(reg: dict, asg: dict) -> list[dict]:
    """Coordinates of an assignment with each identity's CURRENT endpoint record (as of the registry view)."""
    return [{'i': i + 1, 'key': k, 'url': reg['holder_endpoints'].get(k) or ''} for i, k in enumerate(asg['keys'])]


def holders_at(reg: dict, block: int) -> list[dict]:
    return resolve_holders(reg, assignment_at(reg, block))


def active_version(reg: dict, block: int) -> int:
    v = -1
    for i, k in enumerate(reg['key_history']):
        if k['from_block'] <= block:
            v = i
    return v


def meta_from_holders(holders: list[dict], sid_hex: str, e: int, h_manifest: str, h_cert: str, timeout: float = 10.0):
    """I8: manifest + certificate from any holder of the epoch, authenticated by the hashes in contract state."""
    def one(h):
        try:
            st, d, n = post_json(h['url'] + '/meta', {'sid': sid_hex, 'e': e}, timeout=timeout)
            return h, st, d, n
        except Exception as exc:
            return h, 0, {'error': str(exc)}, 0
    with ThreadPoolExecutor(max(1, min(16, len(holders)))) as ex:
        res = list(ex.map(one, holders))
    tried = []
    for h, st, d, n in res:
        tried.append({'i': h['i'], 'status': st})
        if st != 200 or not d.get('manifest') or not d.get('cert'):
            continue
        man, cert = d['manifest'], d['cert']
        if manifest_hash(man).hex() == h_manifest and cert_hash(cert).hex() == h_cert:
            return man, cert, {'source': 'holder', 'holder': h['i'], 'tried': tried, 'bytes': n}
    raise RecoveryError(f'no holder returned metadata matching the anchored hashes ({tried})')


def certified(chain: Chain, sid_hex: str, e: int, height: int | None = None, reg: dict | None = None,
              meta_source: str = 'auto') -> dict:
    """Returns {'certified': bool, 'reason', 'manifest', 'cert', 'holders', 'block', ...}.
    All chain reads at ONE finalized height. meta_source: 'chain' (event logs), 'holders' or 'auto'."""
    fin = chain.finalized_height() if height is None else height
    st = chain.call('get_anchor', sid='0x' + sid_hex, e=e, height=fin)
    if not st or st['block'] == 0:
        return {'certified': False, 'reason': 'no final anchor', 'height': fin}
    out = {'block': st['block'], 'height': fin}
    h_man, h_cert = _strip(st['h_manifest']), _strip(st['h_cert'])
    try:
        reg = reg or registry_at(chain, sid_hex, fin)
        asg = assignment_at(reg, st['block'])
        holders = resolve_holders(reg, asg)
        out['holders'] = holders
        out['gamma'] = asg['version']
        man = cert = None
        if meta_source in ('auto', 'chain'):
            try:
                a = chain.call('anchor_data', sid='0x' + sid_hex, e=e, height=fin)
                if a:
                    mb, cb = bytes.fromhex(_strip(a['manifest'])), bytes.fromhex(_strip(a['cert']))
                    out['anchor_bytes'] = len(mb) + len(cb)
                    man, cert = json.loads(mb), json.loads(cb)
                    if canon(man) != mb or canon(cert) != cb:
                        raise RecoveryError('non-canonical manifest/cert encoding')
                    out['meta_source'] = 'chain'
            except RecoveryError:
                raise
            except Exception as exc:
                if meta_source == 'chain':
                    raise RecoveryError(f'anchor bytes unavailable from chain history: {exc}')
                out['chain_meta_error'] = str(exc)
        if man is None:
            man, cert, info = meta_from_holders(holders, sid_hex, e, h_man, h_cert)
            out['meta_source'] = 'holders'
            out['meta_info'] = info
        if manifest_hash(man).hex() != h_man or cert_hash(cert).hex() != h_cert:
            raise RecoveryError('anchor hash mismatch (contract state)')
        v = active_version(reg, st['block'])  # one key per provider: 0 if registered at or before the anchor block
        if v < 0:
            raise RecoveryError('provider not registered at the anchor block')
        verify_manifest(man, bytes.fromhex(sid_hex), e, reg['ops'][v], assignment_of(asg))
        verify_cert(cert, man)
    except (RecoveryError, ValueError, KeyError, TypeError, AttributeError) as exc:
        out.update(certified=False, reason=f'VOID anchor: {exc}')
        return out
    out.update(manifest=man, cert=cert)
    out.update(certified=True, reason='ok')
    return out
