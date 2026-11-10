"""Command line: python -m hikaudit audit|ports ..."""

from __future__ import annotations

import argparse
import getpass
import json
import os
import sys

from . import __version__
from .checks import HIGH, MEDIUM, run_all, sort_findings
from .client import AuthError, DeviceError, IsapiClient
from .portscan import scan

ICONS = {"HIGH": "[!!]", "MEDIUM": "[! ]", "LOW": "[- ]", "INFO": "[i ]", "PASS": "[ok]"}


def print_report(findings, as_json=False):
    if as_json:
        print(json.dumps([f.to_dict() for f in findings], indent=2))
        return
    for f in findings:
        print(f"{ICONS[f.severity]} {f.severity:<6} {f.title}")
        if f.detail:
            print(f"         {f.detail}")
        if f.fix:
            print(f"         Fix: {f.fix}")
    counts = {s: sum(f.severity == s for f in findings) for s in ICONS}
    print("\nSummary: " + ", ".join(f"{v} {k}" for k, v in counts.items() if v))


def exit_code(findings):
    sevs = {f.severity for f in findings}
    return 2 if HIGH in sevs else 1 if MEDIUM in sevs else 0


def build_parser():
    p = argparse.ArgumentParser(
        prog="hikaudit",
        description="Security self-audit for Hikvision / Hik-Connect devices you own.")
    p.add_argument("--version", action="version", version=__version__)
    sub = p.add_subparsers(dest="cmd", required=True)

    a = sub.add_parser("audit", help="log in to the device and check its settings")
    a.add_argument("--host", required=True, help="device IP on your network, e.g. 192.168.1.64")
    a.add_argument("--user", default="admin")
    a.add_argument("--port", type=int)
    a.add_argument("--https", action="store_true", help="connect over HTTPS")
    a.add_argument("--insecure", action="store_true",
                   help="accept the device's self-signed HTTPS certificate")
    a.add_argument("--skip-ports", action="store_true", help="don't run the port check")
    a.add_argument("--json", action="store_true")

    s = sub.add_parser("ports", help="check which camera ports are reachable")
    s.add_argument("--host", required=True)
    s.add_argument("--public", action="store_true",
                   help="treat any open port as exposed to the internet "
                        "(use when scanning your own public IP from outside)")
    s.add_argument("--json", action="store_true")
    return p


def main(argv=None):
    args = build_parser().parse_args(argv)

    if args.cmd == "ports":
        findings = sort_findings(scan(args.host, public=args.public))
        print_report(findings, args.json)
        return exit_code(findings)

    password = os.environ.get("HIK_PASSWORD") or getpass.getpass(
        f"Password for {args.user}@{args.host}: ")
    client = IsapiClient(args.host, args.user, password, port=args.port,
                         https=args.https, insecure=args.insecure)
    try:
        findings = run_all(client, password)
    except AuthError as e:
        print(f"Error: {e}. Too many failed logins can lock the account.", file=sys.stderr)
        return 3
    except DeviceError as e:
        print(f"Error: {e}", file=sys.stderr)
        return 3
    if not args.skip_ports:
        findings = sort_findings(findings + scan(args.host))
    print_report(findings, args.json)
    return exit_code(findings)
