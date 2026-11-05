"""Throwaway proxy-capture service. No logs, no storage, no outbound requests."""

import hmac
import json
import os
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

CAPTURE_PATH = "/api/capture"
TOKEN_HEADER = "X-Capture-Token"
FORWARDED_HEADER = "X-Forwarded-For"
MIN_TOKEN_LENGTH = 32
MAX_VALUE_LENGTH = 2048
# Only these headers have their values returned. All others: names only.
VALUE_HEADERS = (
    "Forwarded",
    "X-Real-IP",
    "True-Client-IP",
    "CF-Connecting-IP",
    "CF-Connecting-IPv6",
    "X-NF-Client-Connection-IP",
    "Client-IP",
)


class CaptureHandler(BaseHTTPRequestHandler):
    server_version = "capture"
    sys_version = ""
    timeout = 10
    token = b""

    def log_message(self, *_args):
        """Write nothing, so no address reaches the platform's logs through this app."""

    def send_error(self, _code, _message=None, _explain=None):
        self.reply(404, {"error": "Not found."})

    def do_GET(self):
        supplied = self.headers.get(TOKEN_HEADER, "").encode("latin-1", "replace")
        if self.path != CAPTURE_PATH or not hmac.compare_digest(supplied, self.token):
            return self.send_error(404)
        return self.reply(200, self.snapshot())

    def values(self, name):
        return [value[:MAX_VALUE_LENGTH] for value in self.headers.get_all(name) or []]

    def snapshot(self):
        return {
            "peer": self.client_address[0],
            "forwarded_lines": self.values(FORWARDED_HEADER),
            "value_headers": {name: self.values(name) for name in VALUE_HEADERS if name in self.headers},
            "header_names": sorted({name.lower() for name in self.headers.keys()}),
        }

    def reply(self, status, payload):
        body = json.dumps(payload).encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", "application/json; charset=utf-8")
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Cache-Control", "no-store")
        self.end_headers()
        self.wfile.write(body)


def load_token(environ):
    token = environ.get("CAPTURE_TOKEN", "")
    if len(token) < MIN_TOKEN_LENGTH:
        raise SystemExit("CAPTURE_TOKEN must be set, with at least {} characters.".format(MIN_TOKEN_LENGTH))
    return token


def build_server(token, host="0.0.0.0", port=10000):
    handler = type("BoundCaptureHandler", (CaptureHandler,), {"token": token.encode("latin-1", "replace")})
    return ThreadingHTTPServer((host, port), handler)


if __name__ == "__main__":
    build_server(load_token(os.environ), port=int(os.environ.get("PORT", "10000"))).serve_forever()
