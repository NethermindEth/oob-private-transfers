"""Replace(P -> P') and open reconstruction from anchors + holders only (protocol v2).

The replacement P' is a fresh process with its OWN key and sid and an EMPTY data dir. It never reads the original provider's DB, caches, PIR
state, benchmark fixtures or the sender's retained copy: an isolation check scans its config and open files for the
forbidden paths passed by the harness. Appends are enabled only after EVERY anchored epoch of sid is recovered and
its tags restored; otherwise the service stays read-only for recovered epochs and reports the rest as temporarily
unrecoverable.
"""
from __future__ import annotations

import json
import os
import time
from concurrent.futures import ThreadPoolExecutor

from .common import FIELD, REC_BYTES, canon, post_json, unb64
from .epoch import RecoveryError, decode_epoch, fragment_check, noncanonical_slots


def isolation_check(p) -> dict:
    forbidden = [os.path.realpath(f) for f in p.cfg.get('forbidden_paths', [])]
    cfg_text = json.dumps({k: v for k, v in p.cfg.items() if k != 'forbidden_paths'})
    hits = [f for f in forbidden if f in cfg_text]
    files = []
    try:
        import psutil
        me = psutil.Process()
        for proc in [me, *me.children(recursive=True)]:
            try:
                files += [f.path for f in proc.open_files()]
                files += [proc.cwd()]
            except Exception:
                pass
    except ImportError:
        pass
    open_hits = [f for f in files if any(os.path.realpath(f).startswith(x) for x in forbidden)]
    existing = [f for f in forbidden if os.path.exists(f)]
    return {'forbidden_paths': forbidden, 'config_hits': hits, 'open_file_hits': open_hits,
            'forbidden_paths_still_exist': existing, 'open_files_scanned': len(files),
            'ok': not hits and not open_hits}


def fetch_all(holders, sid_hex, e, timeout, coords=None):
    """POST /fetch to the holders of the given coordinates (default: all) in parallel."""
    coords = list(coords) if coords is not None else [h['i'] for h in holders]
    by_i = {h['i']: h for h in holders}

    def one(i):
        t = time.perf_counter()
        h = by_i[i]
        if not h.get('url'):
            return i - 1, 0, {'error': 'no endpoint record'}, 0, 0.0
        try:
            st, data, nbytes = post_json(h['url'] + '/fetch', {'sid': sid_hex, 'e': e}, timeout=timeout)
            return i - 1, st, data, nbytes, time.perf_counter() - t
        except Exception as exc:
            return i - 1, 0, {'error': f'{type(exc).__name__}: {exc}'}, 0, time.perf_counter() - t
    if not coords:
        return []
    with ThreadPoolExecutor(min(len(coords), 64)) as ex:
        return list(ex.map(one, coords))


def fetch_and_decode(holders: list[dict], sid: bytes, e: int, man: dict, timeout: float = 30.0,
                     policy: str = 'all') -> tuple[list[bytes] | None, dict]:
    """Open reconstruction by ANY node, including one that holds no fragment: fetch fragments from the holders of
    the epoch's pinned assignment (coordinates -> identities -> current endpoints), keep only fragments that pass the
    manifest's fragment check (hash in whole_epoch mode; KZG against com_e in fragment_kzg mode), decode any k.
    policy 'all': ask all n holders at once; 'minimal': ask k (data coordinates first), then more only on failure.
    The manifest comes from the chain or a holder, authenticated by the anchor (certify.py). Returns (records, metrics)."""
    k, n = man['k'], man['n']
    m = {'e': e, 'mode': man['mode'], 'k': k, 'n': n, 'q': man['q'], 'fetch_policy': policy}
    t0 = time.perf_counter()
    frags: dict[int, bytes] = {}
    rejected, responses = [], []
    fetch_s = validate_s = 0.0
    fetch_bytes = 0
    pending = [h['i'] for h in holders]
    asked = []
    while len(frags) < k and pending:
        if policy == 'minimal':
            batch, pending = pending[:k - len(frags)], pending[k - len(frags):]
        else:
            batch, pending = pending, []
        asked += batch
        ta = time.perf_counter()
        res = fetch_all(holders, sid.hex(), e, timeout, batch)
        tb = time.perf_counter()
        fetch_s += tb - ta
        fetch_bytes += sum(r[3] for r in res)
        for ix, st, d, nb, dt in res:
            responses.append({'i': ix + 1, 'status': st, 'bytes': nb, 'seconds': dt, 'error': d.get('error')})
            if st != 200:
                continue
            try:
                i, data = d['i'], unb64(d['fragment'])
            except Exception:
                rejected.append({'i': ix + 1, 'what': 'fragment', 'why': 'malformed'})
                continue
            # The coordinate must be the responding identity's own (pinned) coordinate.
            if i != ix + 1:
                rejected.append({'i': ix + 1, 'what': 'fragment', 'why': f'claimed coordinate {i} != holder coordinate'})
                continue
            ok, why = fragment_check(man, i, data)
            if not ok:
                rejected.append({'i': ix + 1, 'what': 'fragment', 'why': why})
                continue
            frags.setdefault(i, data)
        validate_s += time.perf_counter() - tb
    m.update(fetch_s=fetch_s, fetch_bytes=fetch_bytes, validate_s=validate_s, holder_responses=responses,
             coordinates_asked=asked, valid_fragments=sorted(frags), rejected=rejected,
             fragment_bytes_valid=sum(len(f) for f in frags.values()))
    if len(frags) < k:
        m.update(ok=False, reason=f'temporarily unrecoverable: {len(frags)} < k={k} valid fragments')
        return None, m
    t2 = time.perf_counter()
    try:
        recs = decode_epoch(man, frags)
        if man['mode'] == 'whole_epoch' and noncanonical_slots(recs):  # unreachable if an honest holder acked (A-N2)
            raise RecoveryError('non-canonical record')
        # fragment_kzg: slots are stored verbatim : no canonicity filter, no re-encoding comparison
    except RecoveryError as exc:
        m.update(ok=False, reason=str(exc))
        return None, m
    t3 = time.perf_counter()
    m.update(decode_s=t3 - t2, needed_decode=any(t not in frags for t in range(1, k + 1)),
             temp_bytes=sum(len(f) for f in frags.values()) + len(recs) * REC_BYTES, ok=True, total_s=t3 - t0)
    return recs, m


def restore_records(db, e, recs, man, cert, block) -> int:
    """One transaction: records + tags (A4 rule: the earliest anchored (e, j) owns a tag; later duplicates stay
    readable but allocate nothing) + epoch row. Order-independent: if an earlier epoch is
    restored after a later one (e.g. on a recovery retry), it takes over the tag. Returns #tags not newly allocated."""
    from .common import d_rec
    db.execute('BEGIN IMMEDIATE')
    try:
        db.executemany('INSERT INTO records(e,j,rec,d_rec,recovered) VALUES (?,?,?,?,1)',
                       [(e, j, r, d_rec(r)) for j, r in enumerate(recs)])
        before = db.execute('SELECT COUNT(*) FROM tags').fetchone()[0]
        db.executemany('INSERT INTO tags VALUES (?,?,?) ON CONFLICT(tag) DO UPDATE SET e=excluded.e, j=excluded.j '
                       'WHERE (excluded.e, excluded.j) < (tags.e, tags.j)', [(r[:32], e, j) for j, r in enumerate(recs)])
        ignored = len(recs) - (db.execute('SELECT COUNT(*) FROM tags').fetchone()[0] - before)
        db.execute("INSERT INTO epochs(e,state,m_e,manifest,cert,anchor_block,close_reason) VALUES (?,?,?,?,?,?,?)",
                   (e, 'recovered', len(recs), json.dumps(man), json.dumps(cert), block, 'recovered'))
        db.execute('COMMIT')
    except BaseException:
        db.execute('ROLLBACK')
        raise
    return ignored


def recover_epoch(p, e, cinfo) -> dict:
    """Certified epoch e: holders -> records; restore U (A4 rule); rebuild PIR."""
    man, cert = cinfo['manifest'], cinfo['cert']
    t0 = time.perf_counter()
    # Fragments come from the holder set active at the epoch's anchor block, taken from the chain.
    recs, m = fetch_and_decode(cinfo['holders'], bytes.fromhex(man['sid']), e, man, float(p.cfg.get('holder_timeout', 30)),
                               p.cfg.get('recovery_fetch', 'all'))
    if recs is None:
        return m
    t4 = time.perf_counter()
    from .common import d_rec
    with p.dblock:
        m['duplicate_tags_ignored'] = restore_records(p.db, e, recs, man, cert, cinfo['block'])
    t5 = time.perf_counter()
    m['u_restore_s'] = t5 - t4
    p.preprocess(e)
    t6 = time.perf_counter()
    m['pir_rebuild_s'] = t6 - t5
    p.update_epoch(e, metrics={'recovery': m})
    m.update(ok=True, m_e=len(recs), total_s=t6 - t0)
    return m


def recipient_recover(chain, sid_hex: str, e: int, timeout: float = 30.0, policy: str = 'all',
                      meta_source: str = 'auto') -> tuple[list[bytes] | None, dict]:
    """A3/I2: anyone (e.g., the recipient, holding no fragment) reconstructs a certified epoch from the
    chain + the holders of its pinned assignment, without the provider; the whole epoch is decoded
    locally (hides j). meta_source='holders' works without chain event logs ."""
    from .certify import certified, registry_at
    t0 = time.perf_counter()
    fin = chain.finalized_height()
    reg = registry_at(chain, sid_hex, fin)
    c = certified(chain, sid_hex, e, fin, reg, meta_source=meta_source)
    t1 = time.perf_counter()
    if not c['certified']:
        return None, {'ok': False, 'reason': c['reason'], 'certify_check_s': t1 - t0}
    recs, m = fetch_and_decode(c['holders'], bytes.fromhex(sid_hex), e, c['manifest'], timeout, policy)
    m['certify_check_s'] = t1 - t0
    m['anchor_bytes'] = c.get('anchor_bytes')
    m['meta_source'] = c.get('meta_source')
    return recs, m


def lineage(chain, sid_hex: str, height: int) -> tuple[dict, list[str]]:
    """(own registry entry, predecessors) following "continues" links: [P, P's predecessor, ...]."""
    from .certify import registry_at
    me = registry_at(chain, sid_hex, height)
    preds, cur = [], me
    while int(cur.get('continues') or '0x0', 16) != 0:
        c = cur['continues'][2:]
        if c in preds or c == sid_hex or len(preds) > 64:
            raise RecoveryError('cyclic or too long "continues" chain')
        preds.append(c)
        cur = registry_at(chain, c, height)
    return me, preds


def recover_service(p):
    """Replace(P -> P') (protocol v2, ). P' has its OWN key and sid and was registered with
    "continues P" and startEpoch = last_P + 1. With empty storage it lists P's anchors (and those of P's own
    predecessors, if P was itself a replacement) at one finalized height, reconstructs every certified (non-void) epoch
    from the anchor + holders of that epoch's pinned assignment, stores the slots verbatim at the SAME (e, j), restores
    their tags into its own U (earliest slot owns a tag), rebuilds PIR under its own identity, sets e_cur = startEpoch,
    and enables appends only when every such epoch is restored. Receipts it issues (including idempotent retries of
    restored records) name (P', e, j) and are signed by P'."""
    st = p.recovery_state
    st.setdefault('epochs', {})
    st['mode'] = 'replace'
    st['phase'] = 'recovering'
    st['started_at'] = time.time()
    t0 = time.perf_counter()
    try:
        from .certify import certified, registry_at
        fin = p.chain.finalized_height()
        me, preds = lineage(p.chain, p.sid.hex(), fin)
        if me['op_key'][2:] != p.vk.hex():
            raise RecoveryError('this key is not the key registered for this sid')
        start = int(me['start_epoch'])
        if not preds:
            raise RecoveryError('this provider does not declare "continues P" in the registry')
        st.update(height=fin, predecessors=preds, start_epoch=start)
        anchored = []
        for sid in preds:
            anchored += [(sid, e) for e in p.chain.call('list_anchors', sid='0x' + sid, height=fin)]
        late = sorted(e for _, e in anchored if e >= start)
        if late or len({e for _, e in anchored}) != len(anchored):
            raise RecoveryError(f'predecessor anchors at/after the declared start epoch {start} or overlapping: {late}')
        anchored.sort(key=lambda x: x[1])
        st['anchored_epochs'] = [e for _, e in anchored]
        st['anchored'] = [{'sid': s_, 'e': e} for s_, e in anchored]
        with p.dblock:
            if int(p._meta('e_cur')) < start:
                p.db.execute('BEGIN IMMEDIATE')
                p._set_meta('e_cur', start)
                p.db.execute('COMMIT')
        regs = {sid: registry_at(p.chain, sid, fin) for sid in preds}
        done = {r[0] for r in p.db.execute("SELECT e FROM epochs WHERE state='certified'")}
        st.setdefault('void', [])
        for sid, e in anchored:
            if e in done or e in st['void']:
                continue
            tc = time.perf_counter()
            c = certified(p.chain, sid, e, fin, regs[sid], meta_source=p.cfg.get('meta_source', 'auto'))
            if not c['certified']:
                st['void'].append(e)  # VOID anchor: uncertified; never blocks appends (A1)
                st['epochs'][str(e)] = {'e': e, 'origin_sid': sid, 'ok': False, 'void': True, 'reason': c['reason']}
                continue
            try:
                r = recover_epoch(p, e, c)
                r['origin_sid'] = sid
                r['certify_check_s'] = time.perf_counter() - tc - r.get('total_s', 0) if r.get('ok') else None
                st['epochs'][str(e)] = r
            except Exception as exc:
                st['epochs'][str(e)] = {'e': e, 'origin_sid': sid, 'ok': False, 'reason': f'{type(exc).__name__}: {exc}'}
        done = {r[0] for r in p.db.execute("SELECT e FROM epochs WHERE state='certified'")}
        missing = [e for _, e in anchored if e not in done and e not in st['void']]
        st['temporarily_unrecoverable'] = missing
        st['isolation'] = isolation_check(p)
        if not st['isolation']['ok']:
            st['phase'] = 'isolation_violation'
            p.appends_enabled = False
            return
        # Appends only after EVERY certified epoch of the predecessor(s) is restored with its tags.
        p.appends_enabled = not missing
        st['phase'] = 'complete' if not missing else 'read_only_partial'
        st['total_s'] = time.perf_counter() - t0
        st['finished_at'] = time.time()
    except Exception as exc:
        st['phase'] = 'failed'
        st['error'] = f'{type(exc).__name__}: {exc}'
