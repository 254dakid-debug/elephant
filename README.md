# hikaudit

A security check for Hikvision cameras, NVRs and doorbells that you own and use with the **Hik-Connect** app.

It logs in to the device on your home network (the same login you use in the Hik-Connect app or the web page) and **only reads settings**. It never changes anything, never guesses passwords and never tries exploits.

Plain Python 3.9+. No extra packages needed.

## What it checks

| Check | Why it matters |
|---|---|
| Firmware age and known CVEs (CVE-2021-36260, CVE-2017-7921) | Old firmware can let attackers take over the camera without a password |
| UPnP | Can open router ports by itself and put the camera on the internet |
| Hik-Connect status and verification code strength | The code encrypts video sent through the cloud |
| HTTP vs HTTPS | Without HTTPS, your password crosses the network unencrypted |
| Telnet / SSH | Shell access you usually don't need |
| Login lockout | Stops password guessing |
| Basic vs digest auth (web and RTSP) | Basic auth sends the password almost in clear text |
| CGI / ONVIF | Extra ways in |
| User accounts | Old or unused accounts |
| NTP time | Correct timestamps on recordings |
| Admin password strength | Checked on your computer only, never sent anywhere |
| Open ports | What the device exposes on the network |

## Usage

Find the device's IP in the Hik-Connect app (device settings) or on your router, then:

```bash
python3 -m hikaudit audit --host 192.168.1.64 --user admin
# asks for the password; or set HIK_PASSWORD first

# HTTPS with the camera's self-signed certificate
python3 -m hikaudit audit --host 192.168.1.64 --https --insecure

# JSON output
python3 -m hikaudit audit --host 192.168.1.64 --json
```

### Is my camera open to the internet?

Turn off Wi-Fi on your phone (so you're on mobile data), set up a hotspot for a laptop, and scan **your own** home public IP:

```bash
python3 -m hikaudit ports --host <your-public-ip> --public
```

Any open port means a port forward or UPnP is exposing the device. Hik-Connect does not need any open ports.

## Exit codes

`0` nothing serious, `1` medium issues, `2` high issues, `3` couldn't log in or reach the device.

## Notes

- Each failed login counts toward the device's lockout. If the password is wrong, stop and check it, or you may get locked out for about 30 minutes.
- Some settings aren't available on every model or firmware. Those checks are skipped.
- The CVE checks go by firmware build date. They tell you to look closer; they don't prove the device is vulnerable. Confirm against Hikvision's security advisories for your model.
- Only use this on devices you own or have permission to test.

## Tests

```bash
python3 -m unittest discover -s tests -v
```
