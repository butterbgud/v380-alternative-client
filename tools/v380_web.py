#!/usr/bin/env python3
"""Loopback-only browser dashboard for the read-only V380 relay probe."""

from __future__ import annotations

import argparse
import html
import sys
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from urllib.parse import parse_qs

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from v380client.probe import probe_relay

PAGE = """<!doctype html><meta name=viewport content=\"width=device-width,initial-scale=1\">
<title>V380 relay test bench</title><style>
body{font:16px system-ui;max-width:760px;margin:40px auto;padding:0 18px;background:#101418;color:#edf2f7}
input{width:100%;box-sizing:border-box;padding:10px;margin:5px 0 14px;background:#202832;color:inherit;border:1px solid #475569;border-radius:5px}
button{padding:11px 18px;border:0;border-radius:5px;background:#64d38a;font-weight:700}.note{color:#aab7c4}.grid{display:grid;grid-template-columns:1fr 1fr;gap:14px}
pre{white-space:pre-wrap;background:#18202a;padding:16px;border-radius:6px;border-left:4px solid #64d38a}</style>
<h1>V380 relay test bench</h1><p class=note>Loopback-only, read-only authentication and stream negotiation. No video or camera controls yet.</p>
<form method=post action=/probe autocomplete=off><div class=grid>
<label>Relay host<input name=host required value=__HOST__></label><label>Port<input name=port value=8800></label></div>
<div class=grid><label>Device ID<input name=device_id required value=__DEVICE_ID__></label><label>Relay domain<input name=domain value=__DOMAIN__></label></div>
<label>Device username<input name=username required value=__USERNAME__></label><label>Device password<input name=password type=password required></label>
<button>Authenticate and negotiate stream</button></form>{result}"""


def value(values: dict[str, list[str]], name: str, default: str = "") -> str:
    return values.get(name, [default])[0][:512]


class Handler(BaseHTTPRequestHandler):
    server_version = "V380TestBench/0.1"
    defaults = {"host": "", "device_id": "", "domain": "", "username": "tower"}

    def log_message(self, *_args: object) -> None:
        return  # never log form values

    def page(self, result: str = "") -> None:
        page = PAGE.replace("__HOST__", self.defaults["host"])
        page = page.replace("__DEVICE_ID__", self.defaults["device_id"])
        page = page.replace("__DOMAIN__", self.defaults["domain"])
        page = page.replace("__USERNAME__", self.defaults["username"])
        body = page.replace("{result}", result).encode()
        self.send_response(200)
        self.send_header("Content-Type", "text/html; charset=utf-8")
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Cache-Control", "no-store")
        self.end_headers()
        self.wfile.write(body)

    def do_GET(self) -> None:  # noqa: N802
        if self.path != "/":
            self.send_error(404)
            return
        self.page()

    def do_POST(self) -> None:  # noqa: N802
        if self.path != "/probe":
            self.send_error(404)
            return
        length = int(self.headers.get("Content-Length", "0"))
        if length > 8192:
            self.send_error(413)
            return
        values = parse_qs(self.rfile.read(length).decode("utf-8", "replace"))
        password = value(values, "password")
        try:
            result = probe_relay(value(values, "host"), int(value(values, "device_id")),
                                 value(values, "username"), password,
                                 domain=value(values, "domain"), port=int(value(values, "port", "8800")))
            output = ("<pre>Authenticated: result={r}\nStream: status={s} {w}x{h} @ {f}fps\n"
                      "First stream byte: 0x{m:02x}</pre>").format(
                          r=result.auth.result, s=result.stream.status, w=result.stream.width,
                          h=result.stream.height, f=result.stream.fps, m=result.first_stream_marker)
        except Exception as exc:
            output = "<pre>Probe failed: {}</pre>".format(html.escape(str(exc)))
        self.page(output)


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--host", default="127.0.0.1")
    parser.add_argument("--port", type=int, default=8765)
    parser.add_argument("--default-relay", default="")
    parser.add_argument("--default-device-id", default="")
    parser.add_argument("--default-domain", default="")
    parser.add_argument("--default-username", default="tower")
    args = parser.parse_args()
    Handler.defaults = {"host": args.default_relay, "device_id": args.default_device_id,
                        "domain": args.default_domain, "username": args.default_username}
    server = ThreadingHTTPServer((args.host, args.port), Handler)
    print(f"Open http://{args.host}:{args.port}/")
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        pass
    server.server_close()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
