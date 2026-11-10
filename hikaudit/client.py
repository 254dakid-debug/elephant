"""Minimal ISAPI client (stdlib only) for Hikvision devices."""

from __future__ import annotations

import ssl
import urllib.error
import urllib.request
import xml.etree.ElementTree as ET


class AuthError(Exception):
    """Wrong username/password (or the account is locked)."""


class DeviceError(Exception):
    """Device unreachable or returned something unexpected."""


def strip_ns(root: ET.Element) -> ET.Element:
    """Remove XML namespaces so we can use plain tag names."""
    for el in root.iter():
        if isinstance(el.tag, str) and "}" in el.tag:
            el.tag = el.tag.split("}", 1)[1]
    return root


class IsapiClient:
    def __init__(self, host, user, password, port=None, https=False,
                 insecure=False, timeout=8.0):
        scheme = "https" if https else "http"
        port = port or (443 if https else 80)
        self.base = f"{scheme}://{host}:{port}"
        self.https = https
        self.timeout = timeout

        pw = urllib.request.HTTPPasswordMgrWithDefaultRealm()
        pw.add_password(None, self.base, user, password)
        handlers = [
            urllib.request.HTTPDigestAuthHandler(pw),
            urllib.request.HTTPBasicAuthHandler(pw),
        ]
        if https:
            ctx = ssl.create_default_context()
            if insecure:
                # Cameras usually ship a self-signed cert; only skip checks when asked.
                ctx.check_hostname = False
                ctx.verify_mode = ssl.CERT_NONE
            handlers.append(urllib.request.HTTPSHandler(context=ctx))
        self._opener = urllib.request.build_opener(*handlers)

    def get_xml(self, path: str) -> ET.Element | None:
        """GET an ISAPI path. Returns None if the device doesn't support it."""
        try:
            with self._opener.open(self.base + path, timeout=self.timeout) as resp:
                body = resp.read()
        except urllib.error.HTTPError as e:
            if e.code == 401:
                raise AuthError("login rejected (wrong password or account locked)") from e
            if e.code in (403, 404, 405, 501):
                return None
            raise DeviceError(f"{path}: HTTP {e.code}") from e
        except (urllib.error.URLError, OSError) as e:
            raise DeviceError(f"cannot reach {self.base}: {e}") from e
        try:
            return strip_ns(ET.fromstring(body))
        except ET.ParseError:
            return None

    def get_bytes(self, path: str) -> tuple[bytes, str]:
        """GET a raw body (e.g. a JPEG snapshot). Returns (data, content_type)."""
        try:
            with self._opener.open(self.base + path, timeout=self.timeout) as resp:
                return resp.read(), resp.headers.get("Content-Type", "")
        except urllib.error.HTTPError as e:
            if e.code == 401:
                raise AuthError("login rejected (wrong password or account locked)") from e
            raise DeviceError(f"{path}: HTTP {e.code}") from e
        except (urllib.error.URLError, OSError) as e:
            raise DeviceError(f"cannot reach {self.base}: {e}") from e
