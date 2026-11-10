import json
import threading
import unittest
import urllib.request
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

from hikaudit.client import IsapiClient
from viewer import config as cfgmod
from viewer.camera import rtsp_url, snapshot
from viewer.server import make_handler, serve

# A 1x1 JPEG.
JPEG = bytes.fromhex(
    "ffd8ffe000104a46494600010100000100010000ffdb004300080606070605080707"
    "07090908") + b"\x00" * 8 + b"\xff\xd9"


class FakeCam(BaseHTTPRequestHandler):
    def do_GET(self):
        if "Authorization" not in self.headers:
            self.send_response(401)
            self.send_header("WWW-Authenticate", 'Digest realm="c", nonce="n", qop="auth"')
            self.end_headers()
            return
        if self.path.endswith("/picture"):
            self.send_response(200)
            self.send_header("Content-Type", "image/jpeg")
            self.send_header("Content-Length", str(len(JPEG)))
            self.end_headers()
            self.wfile.write(JPEG)
        else:
            self.send_response(404)
            self.end_headers()

    def log_message(self, *a):
        pass


def start(handler_cls):
    srv = ThreadingHTTPServer(("127.0.0.1", 0), handler_cls)
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    return srv


class ConfigTest(unittest.TestCase):
    def test_load_validates_and_reads_env_password(self, ):
        import os
        os.environ["CAM_PW"] = "secret"
        path = "/tmp/cams_test.json"
        with open(path, "w") as fh:
            json.dump({"token": "t", "cameras": [
                {"id": "a", "name": "Front", "host": "10.0.0.1", "password": "env:CAM_PW"}]}, fh)
        cfg = cfgmod.load(path)
        self.assertEqual(cfg.cameras[0].password, "secret")
        self.assertEqual(cfg.token, "t")
        del os.environ["CAM_PW"]

    def test_duplicate_ids_rejected(self):
        path = "/tmp/dup_test.json"
        with open(path, "w") as fh:
            json.dump({"token": "t", "cameras": [
                {"id": "a", "name": "1", "host": "h"},
                {"id": "a", "name": "2", "host": "h"}]}, fh)
        with self.assertRaises(ValueError):
            cfgmod.load(path)

    def test_missing_token_rejected(self):
        import os
        os.environ.pop("VIEWER_TOKEN", None)
        path = "/tmp/notok_test.json"
        with open(path, "w") as fh:
            json.dump({"cameras": [{"id": "a", "name": "1", "host": "h"}]}, fh)
        with self.assertRaises(ValueError):
            cfgmod.load(path)

    def test_gen_token_unique(self):
        self.assertNotEqual(cfgmod.gen_token(), cfgmod.gen_token())


class CameraTest(unittest.TestCase):
    def setUp(self):
        self.srv = start(FakeCam)
        self.port = self.srv.server_address[1]

    def tearDown(self):
        self.srv.shutdown(); self.srv.server_close()

    def test_snapshot_fetches_jpeg(self):
        cam = cfgmod.Camera(id="a", name="Front", host="127.0.0.1",
                            user="admin", password="pw", port=self.port)
        data, ctype = snapshot(cam)
        self.assertTrue(data.startswith(b"\xff\xd8"))
        self.assertEqual(ctype, "image/jpeg")

    def test_rtsp_url(self):
        cam = cfgmod.Camera(id="a", name="F", host="10.0.0.5", user="u", password="p", channel=102)
        self.assertEqual(rtsp_url(cam), "rtsp://u:p@10.0.0.5:554/Streaming/Channels/102")


class ServerTest(unittest.TestCase):
    def setUp(self):
        self.cam_srv = start(FakeCam)
        cam_port = self.cam_srv.server_address[1]
        self.cfg = cfgmod.Config(
            token="sekret",
            cameras=[cfgmod.Camera(id="front", name="Front Door", host="127.0.0.1",
                                   user="admin", password="pw", port=cam_port)])
        self.view = serve(self.cfg)
        self.vport = self.view.server_address[1]
        threading.Thread(target=self.view.serve_forever, daemon=True).start()

    def tearDown(self):
        self.view.shutdown(); self.view.server_close()
        self.cam_srv.shutdown(); self.cam_srv.server_close()

    def _get(self, path):
        req = urllib.request.Request(f"http://127.0.0.1:{self.vport}{path}")
        return urllib.request.urlopen(req, timeout=5)

    def test_no_token_is_unauthorized(self):
        with self.assertRaises(urllib.error.HTTPError) as cm:
            self._get("/")
        self.assertEqual(cm.exception.code, 401)

    def test_wrong_token_is_unauthorized(self):
        with self.assertRaises(urllib.error.HTTPError) as cm:
            self._get("/?token=nope")
        self.assertEqual(cm.exception.code, 401)

    def test_page_and_cookie(self):
        resp = self._get("/?token=sekret")
        body = resp.read().decode()
        self.assertIn("Front Door", body)
        self.assertIn('src="/stream/front"', body)
        self.assertIn("viewer_token=sekret", resp.headers.get("Set-Cookie", ""))

    def test_api_cameras(self):
        resp = self._get("/api/cameras?token=sekret")
        self.assertEqual(json.load(resp), [{"id": "front", "name": "Front Door"}])

    def test_snapshot_proxies_jpeg(self):
        resp = self._get("/snapshot/front?token=sekret")
        data = resp.read()
        self.assertTrue(data.startswith(b"\xff\xd8"))
        self.assertEqual(resp.headers.get("Content-Type"), "image/jpeg")

    def test_unknown_camera_404(self):
        with self.assertRaises(urllib.error.HTTPError) as cm:
            self._get("/snapshot/nope?token=sekret")
        self.assertEqual(cm.exception.code, 404)

    def test_stream_single_frame(self):
        # Drive the MJPEG generator directly for a bounded number of frames.
        handler_cls = make_handler(self.cfg)
        captured = []

        class Fake(handler_cls):
            def __init__(self):
                pass
            def send_response(self, *a): pass
            def send_header(self, *a): pass
            def end_headers(self): pass
            class _W:
                def write(self, b): captured.append(b)
            wfile = _W()

        Fake()._stream("front", max_frames=1)
        blob = b"".join(captured)
        self.assertIn(b"--frame", blob)
        self.assertIn(b"image/jpeg", blob)
        self.assertIn(b"\xff\xd8", blob)


if __name__ == "__main__":
    unittest.main()
