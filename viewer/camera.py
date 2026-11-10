"""Fetch snapshots from a Hikvision camera over ISAPI."""

from __future__ import annotations

from hikaudit.client import IsapiClient

from .config import Camera


def client_for(cam: Camera) -> IsapiClient:
    return IsapiClient(cam.host, cam.user, cam.password, port=cam.port,
                       https=cam.https, insecure=cam.insecure, timeout=6.0)


def snapshot(cam: Camera, client: IsapiClient | None = None) -> tuple[bytes, str]:
    """Return one JPEG frame (bytes, content_type) from the camera."""
    client = client or client_for(cam)
    path = f"/ISAPI/Streaming/channels/{cam.channel}/picture"
    data, ctype = client.get_bytes(path)
    if not ctype:
        ctype = "image/jpeg"
    return data, ctype


def rtsp_url(cam: Camera) -> str:
    """The direct RTSP URL, for players like VLC or ffmpeg."""
    port = 554
    # ISAPI channel 101 -> RTSP stream 101; sub stream 102, etc.
    return (f"rtsp://{cam.user}:{cam.password}@{cam.host}:{port}"
            f"/Streaming/Channels/{cam.channel}")
