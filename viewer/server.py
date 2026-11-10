"""A small self-hosted web viewer. Stdlib only.

Routes (all need the token):
  GET /                 mobile page with a live grid
  GET /api/cameras      JSON list of cameras
  GET /snapshot/<id>    one JPEG frame
  GET /stream/<id>      MJPEG stream (live view in a plain <img>)
"""

from __future__ import annotations

import argparse
import html
import json
import secrets
import sys
import time
from http import HTTPStatus
from http.cookies import SimpleCookie
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import parse_qs, urlparse

from hikaudit.client import AuthError, DeviceError

from . import __version__, config as cfgmod
from .camera import client_for, snapshot

# How often the MJPEG stream grabs a new frame, and how long a camera error
# waits before retrying, in seconds.
FRAME_INTERVAL = 1.0
ERROR_BACKOFF = 2.0


def page_html(cameras) -> bytes:
    cards = "\n".join(
        f'<figure><img src="/stream/{html.escape(c.id)}" alt="{html.escape(c.name)}" '
        f'loading="lazy"><figcaption>{html.escape(c.name)}</figcaption></figure>'
        for c in cameras)
    doc = f"""<!doctype html>
<html lang="en"><head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>Cameras</title>
<style>
  :root {{ color-scheme: dark; }}
  body {{ margin:0; background:#111; color:#eee; font:16px system-ui,sans-serif; }}
  header {{ padding:12px 16px; font-weight:600; position:sticky; top:0; background:#111; }}
  main {{ display:grid; gap:10px; padding:10px;
          grid-template-columns:repeat(auto-fit,minmax(320px,1fr)); }}
  figure {{ margin:0; background:#000; border-radius:10px; overflow:hidden; }}
  img {{ width:100%; display:block; aspect-ratio:16/9; object-fit:cover; background:#000; }}
  figcaption {{ padding:6px 10px; font-size:14px; color:#bbb; }}
</style></head>
<body><header>My Cameras</header>
<main>{cards}</main></body></html>"""
    return doc.encode("utf-8")


def make_handler(config: cfgmod.Config):
    class Handler(BaseHTTPRequestHandler):
        server_version = f"viewer/{__version__}"
        protocol_version = "HTTP/1.1"

        # -- auth --------------------------------------------------------
        def _token_ok(self, query) -> bool:
            supplied = ""
            if "token" in query:
                supplied = query["token"][0]
            else:
                cookie = SimpleCookie(self.headers.get("Cookie", ""))
                if "viewer_token" in cookie:
                    supplied = cookie["viewer_token"].value
            return bool(supplied) and secrets.compare_digest(supplied, config.token)

        def _deny(self):
            self.send_error(HTTPStatus.UNAUTHORIZED, "token required or wrong")

        # -- helpers -----------------------------------------------------
        def _send(self, code, body: bytes, ctype, extra=None):
            self.send_response(code)
            self.send_header("Content-Type", ctype)
            self.send_header("Content-Length", str(len(body)))
            self.send_header("Cache-Control", "no-store")
            for k, v in (extra or {}):
                self.send_header(k, v)
            self.end_headers()
            self.wfile.write(body)

        def log_message(self, *a):
            pass

        # -- routing -----------------------------------------------------
        def do_GET(self):
            parsed = urlparse(self.path)
            query = parse_qs(parsed.query)
            if not self._token_ok(query):
                return self._deny()
            path = parsed.path
            set_cookie = None
            if "token" in query:
                # Stash the token so <img> requests don't need it in the URL.
                set_cookie = [("Set-Cookie",
                               f"viewer_token={config.token}; Path=/; HttpOnly; SameSite=Strict")]

            if path == "/":
                return self._send(HTTPStatus.OK, page_html(config.cameras),
                                  "text/html; charset=utf-8", set_cookie)
            if path == "/api/cameras":
                body = json.dumps([{"id": c.id, "name": c.name} for c in config.cameras]).encode()
                return self._send(HTTPStatus.OK, body, "application/json", set_cookie)
            if path.startswith("/snapshot/"):
                return self._snapshot(path[len("/snapshot/"):])
            if path.startswith("/stream/"):
                return self._stream(path[len("/stream/"):])
            self.send_error(HTTPStatus.NOT_FOUND)

        def _snapshot(self, cam_id):
            cam = config.camera(cam_id)
            if cam is None:
                return self.send_error(HTTPStatus.NOT_FOUND, "no such camera")
            try:
                data, ctype = snapshot(cam)
            except (AuthError, DeviceError) as e:
                return self.send_error(HTTPStatus.BAD_GATEWAY, str(e))
            self._send(HTTPStatus.OK, data, ctype or "image/jpeg")

        def _stream(self, cam_id, max_frames: int | None = None):
            cam = config.camera(cam_id)
            if cam is None:
                return self.send_error(HTTPStatus.NOT_FOUND, "no such camera")
            boundary = "frame"
            self.send_response(HTTPStatus.OK)
            self.send_header("Content-Type",
                             f"multipart/x-mixed-replace; boundary={boundary}")
            self.send_header("Cache-Control", "no-store")
            self.end_headers()
            client = client_for(cam)  # reuse one connection/auth for the whole stream
            sent = 0
            try:
                while max_frames is None or sent < max_frames:
                    try:
                        data, ctype = snapshot(cam, client)
                    except (AuthError, DeviceError):
                        time.sleep(ERROR_BACKOFF)
                        continue
                    head = (f"--{boundary}\r\nContent-Type: {ctype or 'image/jpeg'}\r\n"
                            f"Content-Length: {len(data)}\r\n\r\n").encode()
                    self.wfile.write(head)
                    self.wfile.write(data)
                    self.wfile.write(b"\r\n")
                    sent += 1
                    time.sleep(FRAME_INTERVAL)
            except (BrokenPipeError, ConnectionResetError):
                pass  # phone closed the tab; normal.

    return Handler


def serve(config: cfgmod.Config, server_cls=ThreadingHTTPServer):
    httpd = server_cls((config.bind, config.port), make_handler(config))
    return httpd


def build_parser():
    p = argparse.ArgumentParser(prog="viewer",
                                description="Self-hosted mobile viewer for your own Hikvision cameras.")
    p.add_argument("--version", action="version", version=__version__)
    sub = p.add_subparsers(dest="cmd", required=True)
    r = sub.add_parser("run", help="start the web viewer")
    r.add_argument("--config", required=True, help="path to cameras.json")
    sub.add_parser("gen-token", help="print a fresh random access token")
    return p


def main(argv=None):
    args = build_parser().parse_args(argv)
    if args.cmd == "gen-token":
        print(cfgmod.gen_token())
        return 0
    try:
        config = cfgmod.load(args.config)
    except (OSError, ValueError) as e:
        print(f"Config error: {e}", file=sys.stderr)
        return 2
    httpd = serve(config)
    url = f"http://{config.bind}:{config.port}/?token={config.token}"
    print(f"Viewer running. Open on your phone (over VPN):\n  {url}")
    if config.bind == "127.0.0.1":
        print("Note: bound to localhost. Set \"bind\":\"0.0.0.0\" to reach it over your VPN/LAN.")
    try:
        httpd.serve_forever()
    except KeyboardInterrupt:
        print("\nStopping.")
    finally:
        httpd.server_close()
    return 0
