"""Owned loopback-only HTTP fixture for the RiskLens demonstration."""
import argparse
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
import json
from pathlib import Path


def make_handler(state_file):
    class Handler(BaseHTTPRequestHandler):
        def do_GET(self):
            state = json.loads(state_file.read_text(encoding="utf-8-sig")) if state_file.exists() else {}
            body = b"RiskLens owned localhost lab\n"
            self.send_response(200 if self.path in {"/", "/docs"} else 404)
            self.send_header("Content-Type", "text/plain; charset=utf-8")
            self.send_header("Content-Length", str(len(body)))
            if state.get("nosniff"):
                self.send_header("X-Content-Type-Options", "nosniff")
            self.end_headers()
            self.wfile.write(body)

        def log_message(self, *args):
            pass
    return Handler


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("--port", type=int, default=8080)
    parser.add_argument("--state", type=Path, default=Path("artifacts/lab-state.json"))
    options = parser.parse_args()
    server = ThreadingHTTPServer(("127.0.0.1", options.port), make_handler(options.state))
    print(f"Owned lab: http://127.0.0.1:{options.port}; header state: {options.state}", flush=True)
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        pass
    finally:
        server.server_close()
