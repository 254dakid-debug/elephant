# viewer — your own Hik-Connect alternative

A small web app that shows your Hikvision cameras on your phone, **without the Hik-Connect app or cloud account**. It talks straight to your own cameras over their built-in ISAPI interface, using your device login. You own the whole path.

Plain Python 3.9+, no extra packages.

## How it works

```
phone  ──VPN──►  this viewer (a PC/Pi at home)  ──ISAPI──►  your cameras
```

- The viewer pulls JPEG frames from each camera and streams them to your phone's browser as live video (MJPEG in a plain `<img>`).
- A **VPN** (WireGuard or Tailscale) carries your phone into your home network when you're away. The viewer and cameras never touch the public internet.
- Every request to the viewer needs a secret **token**, so being on the VPN isn't enough by itself.

This is why no account copying is needed or wanted: there's no third-party cloud in the picture. Copying a Hik-Connect account would just be impersonating yourself to Hikvision's servers, which they block.

## Setup

1. **Make a token:**
   ```bash
   python3 -m viewer gen-token
   ```
2. **Make a config** from the example:
   ```bash
   cp viewer/cameras.example.json cameras.json
   # put the token in it, list your cameras, set each host IP
   export CAM_FRONT_PW='your-camera-password'   # keeps passwords out of the file
   ```
   `channel`: `101` = camera 1 full quality, `102` = camera 1 lower quality (lighter on phones/data). On an NVR, `201`, `301`, … are cameras 2, 3, …
3. **Run it:**
   ```bash
   python3 -m viewer run --config cameras.json
   ```
   It prints a URL with the token. Open it on your phone.

To reach it over the VPN from your phone, set `"bind": "0.0.0.0"` in the config.

## Remote access (the VPN part)

Easiest is **Tailscale**: install it on the home machine running the viewer and on your phone, both signed into the same account. Then on your phone open `http://<home-machine-tailscale-ip>:8088/?token=...`. Nothing is exposed to the internet and you forward no ports.

WireGuard works too if you'd rather self-host the VPN on your router.

**Don't** just port-forward 8088 to the internet. Use the VPN.

## Direct RTSP (optional)

Each camera also has a direct RTSP URL for VLC, ffmpeg or other apps:
```
rtsp://user:pass@192.168.1.64:554/Streaming/Channels/101
```

## Limits

- MJPEG (frame-by-frame) is simple and works in any browser, but uses more data than H.264. Use sub-stream channels (`102`) on mobile data.
- No audio, no two-way talk, no PTZ yet. Those are possible over ISAPI and can be added.
- Run `hikaudit` first to make sure the cameras themselves are locked down.

## Tests

```bash
python3 -m unittest discover -s tests -v
```
