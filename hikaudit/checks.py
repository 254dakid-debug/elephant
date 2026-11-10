"""Security checks. Each check takes a client with get_xml(path) and returns Findings."""

from __future__ import annotations

import re
from dataclasses import asdict, dataclass
from datetime import date

HIGH, MEDIUM, LOW, INFO, PASS = "HIGH", "MEDIUM", "LOW", "INFO", "PASS"
SEVERITY_ORDER = [HIGH, MEDIUM, LOW, INFO, PASS]


@dataclass
class Finding:
    id: str
    severity: str
    title: str
    detail: str = ""
    fix: str = ""

    def to_dict(self):
        return asdict(self)


def _enabled(el, tag="enabled"):
    """Read a true/false flag; returns None if missing."""
    if el is None:
        return None
    val = el.findtext(tag)
    if val is None:
        val = el.findtext(".//" + tag)
    if val is None:
        return None
    return val.strip().lower() == "true"


# --- firmware ---------------------------------------------------------------

def parse_build(text: str | None) -> date | None:
    """'build 210628' -> date(2021, 6, 28)."""
    m = re.search(r"(\d{2})(\d{2})(\d{2})", text or "")
    if not m:
        return None
    yy, mm, dd = (int(x) for x in m.groups())
    try:
        return date(2000 + yy, mm, dd)
    except ValueError:
        return None


def parse_version(text: str | None) -> tuple[int, ...] | None:
    m = re.search(r"(\d+)\.(\d+)(?:\.(\d+))?", text or "")
    if not m:
        return None
    return tuple(int(x) for x in m.groups() if x is not None)


def check_firmware(c, today: date | None = None):
    today = today or date.today()
    info = c.get_xml("/ISAPI/System/deviceInfo")
    if info is None:
        return [Finding("firmware", INFO, "Could not read device info")]
    model = info.findtext("model") or "?"
    fw = info.findtext("firmwareVersion") or "?"
    rel = info.findtext("firmwareReleasedDate") or ""
    build = parse_build(rel)
    ver = parse_version(fw)

    out = [Finding("device", INFO, f"{model}, firmware {fw} {rel}".strip(),
                   f"Device type: {info.findtext('deviceType') or '?'}, "
                   f"serial: {info.findtext('serialNumber') or '?'}")]
    if build is None:
        out.append(Finding("firmware-age", INFO, "Firmware build date unknown",
                           fix="Check Hikvision's site for the latest firmware for this model."))
        return out

    flagged = False
    if build < date(2021, 6, 28):
        flagged = True
        out.append(Finding(
            "CVE-2021-36260", HIGH,
            "Firmware may be vulnerable to CVE-2021-36260 (remote command injection)",
            f"Build {build} is older than the June 2021 fix. Many Hikvision cameras on "
            "older builds can be taken over without a password.",
            "Update the firmware now. Check the Hikvision security advisory "
            "(HSRC-202109-01) for your model."))
    if ver and (5, 2) <= ver[:2] <= (5, 4) and build < date(2017, 5, 12):
        flagged = True
        out.append(Finding(
            "CVE-2017-7921", HIGH,
            "Firmware may be vulnerable to CVE-2017-7921 (login bypass)",
            f"Version {fw} build {build} falls in the affected range.",
            "Update the firmware."))
    age_days = (today - build).days
    if age_days > 3 * 365:
        flagged = True
        out.append(Finding(
            "firmware-age", MEDIUM, f"Firmware is about {age_days // 365} years old",
            "Old firmware often has known security holes.",
            "Install the newest firmware for this exact model from Hikvision's site."))
    if not flagged:
        out.append(Finding("firmware-age", PASS, f"Firmware build {build} is recent"))
    return out


# --- network services -------------------------------------------------------

def check_upnp(c):
    el = c.get_xml("/ISAPI/System/Network/UPnP")
    on = _enabled(el)
    if on is None:
        return []
    if on:
        return [Finding("upnp", HIGH, "UPnP is on",
                        "The device can open ports on your router by itself, which "
                        "puts the camera directly on the internet.",
                        "Turn off UPnP: Configuration > Network > Advanced > NAT. "
                        "Hik-Connect works without it.")]
    return [Finding("upnp", PASS, "UPnP is off")]


def check_platform_access(c):
    el = c.get_xml("/ISAPI/System/Network/EZVIZ")
    on = _enabled(el)
    if on is None:
        return [Finding("hik-connect", INFO, "Hik-Connect status not available")]
    if not on:
        return [Finding("hik-connect", INFO, "Hik-Connect (platform access) is off")]
    out = []
    reg = el.findtext("registerStatus")
    status = "registered" if (reg or "").lower() == "true" else "not registered"
    out.append(Finding("hik-connect", INFO, f"Hik-Connect is on ({status})"))
    code = el.findtext("verificationCode")
    if code:
        weak = (len(code) < 6 or len(set(code)) <= 2
                or code.upper() in {"ABCDEF", "123456", "ABCDEFG", "QWERTY", "AAAAAA"})
        if weak:
            out.append(Finding("verification-code", MEDIUM,
                               "Hik-Connect verification code is weak",
                               "This code encrypts the video sent through the cloud.",
                               "Set a random code of 6+ characters in Platform Access."))
        else:
            out.append(Finding("verification-code", PASS,
                               "Verification code looks reasonable"))
    return out


def check_admin_access(c):
    el = c.get_xml("/ISAPI/Security/adminAccesses")
    if el is None:
        return []
    protos = {}
    for p in el.iter("AdminAccessProtocol"):
        name = (p.findtext("protocol") or "").upper()
        protos[name] = (_enabled(p), p.findtext("portNo"))
    out = []
    http_on = protos.get("HTTP", (None,))[0]
    https_on = protos.get("HTTPS", (None,))[0]
    if http_on and not https_on:
        out.append(Finding("https", MEDIUM, "Web access uses HTTP only",
                           "Logins and settings travel unencrypted on your network.",
                           "Turn on HTTPS: Configuration > Network > Advanced > HTTPS."))
    elif https_on:
        out.append(Finding("https", PASS, "HTTPS is on"))
    listing = ", ".join(f"{k}:{v[1]}" for k, v in protos.items() if v[0])
    if listing:
        out.append(Finding("services", INFO, f"Open services: {listing}",
                           fix="Never port-forward these on your router. "
                               "Use Hik-Connect for remote access instead."))
    return out


def check_shell_services(c):
    out = []
    t = _enabled(c.get_xml("/ISAPI/System/Network/telnetd"))
    if t:
        out.append(Finding("telnet", HIGH, "Telnet is on",
                           "Telnet sends passwords in clear text and gives shell access.",
                           "Turn off Telnet."))
    elif t is False:
        out.append(Finding("telnet", PASS, "Telnet is off"))
    s = _enabled(c.get_xml("/ISAPI/System/Network/ssh"))
    if s:
        out.append(Finding("ssh", MEDIUM, "SSH is on",
                           "Only needed for support work.",
                           "Turn off SSH: Configuration > System > Security."))
    elif s is False:
        out.append(Finding("ssh", PASS, "SSH is off"))
    return out


def check_integrations(c):
    el = c.get_xml("/ISAPI/System/Network/Integrate")
    if el is None:
        return []
    out = []
    for tag, sev, why in [
        ("CGI", LOW, "Old CGI interface is extra attack surface."),
        ("ONVIF", LOW, "ONVIF has its own user list. Make sure it has a strong password."),
    ]:
        sub = el.find(tag)
        if _enabled(sub, "enable"):
            out.append(Finding(tag.lower(), sev, f"{tag} is on", why,
                               f"Turn off {tag} unless another system needs it."))
    return out


# --- authentication ---------------------------------------------------------

def check_lockout(c):
    el = c.get_xml("/ISAPI/Security/illegalLoginLock")
    on = _enabled(el)
    if on is None:
        return []
    if not on:
        return [Finding("lockout", MEDIUM, "Login lockout is off",
                        "Attackers can guess passwords forever.",
                        "Turn on Illegal Login Lock: Configuration > System > Security.")]
    n = el.findtext("maxIllegalLoginTimes")
    if n and n.isdigit() and int(n) > 10:
        return [Finding("lockout", LOW, f"Lockout allows {n} tries",
                        fix="Lower it to 5-7 attempts.")]
    return [Finding("lockout", PASS, "Login lockout is on")]


def check_auth_types(c):
    out = []
    for path, name in [("/ISAPI/Security/webCertificate", "Web"),
                       ("/ISAPI/Security/RTSPCertificate", "RTSP (video stream)")]:
        el = c.get_xml(path)
        if el is None:
            continue
        kind = (el.findtext(".//certificateType") or "").lower()
        if "basic" in kind:
            out.append(Finding(f"auth-{name.split()[0].lower()}", MEDIUM,
                               f"{name} login allows Basic auth",
                               "Basic auth sends the password almost in clear text.",
                               f"Set {name} authentication to 'digest' only."))
        elif kind:
            out.append(Finding(f"auth-{name.split()[0].lower()}", PASS,
                               f"{name} uses digest auth"))
    return out


def check_users(c):
    el = c.get_xml("/ISAPI/Security/users")
    if el is None:
        return []
    names = [u.findtext("userName") for u in el.iter("User") if u.findtext("userName")]
    if not names:
        return []
    out = [Finding("users", INFO, f"{len(names)} account(s): {', '.join(names)}",
                   fix="Delete accounts nobody uses. Give family members 'Operator' "
                       "or 'User' rights, not admin.")]
    return out


def check_time(c):
    el = c.get_xml("/ISAPI/System/time")
    if el is None:
        return []
    mode = (el.findtext("timeMode") or "").upper()
    if mode and mode != "NTP":
        return [Finding("ntp", LOW, "Clock is set by hand",
                        "Wrong timestamps make recordings less useful as evidence.",
                        "Turn on NTP time sync.")]
    return [Finding("ntp", PASS, "Clock syncs with NTP")] if mode else []


COMMON_PASSWORDS = {"12345", "123456", "12345678", "123456789", "admin", "admin123",
                    "password", "hikvision", "abc12345", "1234567890", "admin12345"}


def check_password(password: str):
    """Check the password you logged in with. Runs locally, nothing is sent."""
    if password.lower() in COMMON_PASSWORDS:
        return [Finding("password", HIGH, "Admin password is a well-known default",
                        fix="Change it now to a long, unique password.")]
    classes = sum(bool(re.search(p, password))
                  for p in (r"[a-z]", r"[A-Z]", r"\d", r"[^A-Za-z0-9]"))
    if len(password) < 10 or classes < 3:
        return [Finding("password", MEDIUM, "Admin password is weak",
                        "Use 10+ characters with letters, numbers and symbols.",
                        "Change it: Configuration > System > User Management.")]
    return [Finding("password", PASS, "Admin password looks strong")]


DEVICE_CHECKS = [
    check_firmware, check_upnp, check_platform_access, check_admin_access,
    check_shell_services, check_integrations, check_lockout, check_auth_types,
    check_users, check_time,
]


def run_all(client, password: str | None = None):
    findings = []
    for check in DEVICE_CHECKS:
        findings.extend(check(client))
    if password is not None:
        findings.extend(check_password(password))
    return sort_findings(findings)


def sort_findings(findings):
    return sorted(findings, key=lambda f: SEVERITY_ORDER.index(f.severity))
