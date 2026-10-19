"""Minimal threaded HTTP server with JSON/octet-stream helpers, fault hooks and an observation log."""
from __future__ import annotations

import json
import socket
import threading
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from socketserver import TCPServer


class DropConnection(Exception):
    """Handler raises this to close the socket without any HTTP response (fault injection)."""


class Reply:
    def __init__(self, status=200, body: bytes | dict | list = b'', ctype=None):
        if isinstance(body, (dict, list)):
            body = json.dumps(body, sort_keys=True, separators=(',', ':')).encode()
            ctype = ctype or 'application/json'
        self.status, self.body, self.ctype = status, body, ctype or 'application/octet-stream'


def err(status, msg, **extra):
    return Reply(status, dict(error=msg, **extra))


class LoopbackServer(ThreadingHTTPServer):
    daemon_threads = True
    request_queue_size = 256

    def server_bind(self):
        TCPServer.server_bind(self)  # skip reverse DNS
        self.server_name, self.server_port = 'localhost', self.server_address[1]


def serve(port: int, app, name: str = 'svc'):
    """app.handle(method, path, body: bytes, headers) -> Reply. Blocks forever."""

    class Handler(BaseHTTPRequestHandler):
        protocol_version = 'HTTP/1.1'

        def _do(self, method):
            size = int(self.headers.get('Content-Length', '0') or 0)
            if size > 512 * 1024 * 1024:
                self.send_error(413)
                return
            body = self.rfile.read(size) if size else b''
            t = time.perf_counter()
            try:
                rep = app.handle(method, self.path, body, self.headers)
            except DropConnection:
                try:
                    self.connection.shutdown(socket.SHUT_RDWR)
                except OSError:
                    pass
                self.close_connection = True
                return
            except Exception as exc:  # never leak a traceback page; report as 500 JSON
                rep = err(500, f'{type(exc).__name__}: {exc}')
            self.send_response(rep.status)
            self.send_header('Content-Type', rep.ctype)
            self.send_header('Content-Length', str(len(rep.body)))
            self.send_header('X-Server-Seconds', f'{time.perf_counter() - t:.6f}')
            self.end_headers()
            self.wfile.write(rep.body)

        def do_GET(self):
            self._do('GET')

        def do_POST(self):
            self._do('POST')

        def log_message(self, *a):
            pass

    server = LoopbackServer(('127.0.0.1', port), Handler)
    try:
        server.serve_forever(poll_interval=0.1)
    finally:
        server.server_close()


class JsonLog:
    def __init__(self, path):
        self.path = path
        self.lock = threading.Lock()

    def write(self, **rec):
        rec['t'] = time.time()
        with self.lock, open(self.path, 'a') as f:
            f.write(json.dumps(rec, sort_keys=True) + '\n')
