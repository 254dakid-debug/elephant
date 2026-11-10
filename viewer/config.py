"""Load the list of cameras and the viewer's own access token."""

from __future__ import annotations

import json
import os
import secrets
from dataclasses import dataclass, field


@dataclass
class Camera:
    id: str
    name: str
    host: str
    user: str = "admin"
    password: str = ""
    channel: int = 101  # ISAPI channel: 101 = cam 1 main stream, 102 = sub stream
    port: int | None = None
    https: bool = False
    insecure: bool = False

    def __post_init__(self):
        # Let a password live in the environment instead of the file on disk.
        if self.password.startswith("env:"):
            self.password = os.environ.get(self.password[4:], "")


@dataclass
class Config:
    cameras: list[Camera] = field(default_factory=list)
    token: str = ""  # required in every request to the viewer
    bind: str = "127.0.0.1"
    port: int = 8088

    def camera(self, cam_id: str) -> Camera | None:
        return next((c for c in self.cameras if c.id == cam_id), None)


def load(path: str) -> Config:
    with open(path, encoding="utf-8") as fh:
        raw = json.load(fh)
    cams = [Camera(**c) for c in raw.get("cameras", [])]
    if not cams:
        raise ValueError("config has no cameras")
    ids = [c.id for c in cams]
    if len(ids) != len(set(ids)):
        raise ValueError("camera ids must be unique")
    token = raw.get("token") or os.environ.get("VIEWER_TOKEN", "")
    if not token:
        raise ValueError(
            "no token set. Add a 'token' to the config or set VIEWER_TOKEN. "
            "Generate one with: python -m viewer gen-token")
    return Config(cameras=cams, token=token,
                  bind=raw.get("bind", "127.0.0.1"), port=int(raw.get("port", 8088)))


def gen_token() -> str:
    return secrets.token_urlsafe(24)
