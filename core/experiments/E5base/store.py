"""Plain encrypted-backup store for the E5 baseline (e): an independent blob store with no admission, no proofs,
no certification and no PIR. Objects live in buckets (one bucket = one time window, like an epoch) in SQLite with
synchronous commits, as for the OOB providers.

POST /obj/<bucket>/<id>   store bytes (write-once)      GET /obj/<bucket>/<id>   fetch one object (not private)
GET  /bucket/<bucket>     all objects of a bucket, each as 16-byte id + 4-byte length + bytes (private whole-bucket read)
GET  /status              object count and stored bytes
Run: python -m core.experiments.E5base.store <port> <data_dir>
"""
from __future__ import annotations

import sqlite3
import sys
import threading
from pathlib import Path

from core.oobsvc.httpserv import Reply, err, serve


class Store:
    def __init__(self, data_dir: str):
        Path(data_dir).mkdir(parents=True, exist_ok=True)
        self.db = sqlite3.connect(Path(data_dir) / 'store.sqlite3', check_same_thread=False, isolation_level=None)
        self.db.execute('PRAGMA synchronous=FULL')
        self.db.execute('PRAGMA journal_mode=WAL')
        self.db.execute('CREATE TABLE IF NOT EXISTS obj(bucket TEXT, id BLOB, data BLOB, PRIMARY KEY(bucket, id))')
        self.lock = threading.Lock()

    def handle(self, method, path, body, headers):
        parts = path.strip('/').split('/')
        if path == '/status':
            n, b = self.db.execute('SELECT COUNT(*), COALESCE(SUM(LENGTH(data)),0) FROM obj').fetchone()
            return Reply(200, {'objects': n, 'bytes': b})
        if parts[0] == 'obj' and len(parts) == 3:
            bucket, oid = parts[1], bytes.fromhex(parts[2])
            if method == 'POST':
                with self.lock:
                    try:
                        self.db.execute('INSERT INTO obj VALUES (?,?,?)', (bucket, oid, body))
                    except sqlite3.IntegrityError:
                        return err(409, 'exists')
                return Reply(200, {'stored': len(body)})
            row = self.db.execute('SELECT data FROM obj WHERE bucket=? AND id=?', (bucket, oid)).fetchone()
            return Reply(200, bytes(row[0])) if row else err(404, 'no object')
        if parts[0] == 'bucket' and len(parts) == 2 and method == 'GET':
            rows = self.db.execute('SELECT id, data FROM obj WHERE bucket=? ORDER BY id', (parts[1],)).fetchall()
            return Reply(200, b''.join(bytes(i) + len(d).to_bytes(4, 'big') + bytes(d) for i, d in rows))
        return err(404, 'unknown endpoint')


def main():
    port, data_dir = int(sys.argv[1]), sys.argv[2]
    s = Store(data_dir)
    (Path(data_dir) / 'READY').write_text(str(port))
    serve(port, s, f'store-{port}')


if __name__ == '__main__':
    main()
