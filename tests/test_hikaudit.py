import http.server
import io
import threading
import unittest
from contextlib import redirect_stdout
from datetime import date

from hikaudit import checks
from hikaudit.cli import main
from hikaudit.client import AuthError, IsapiClient, strip_ns
import xml.etree.ElementTree as ET

NS = 'xmlns="http://www.hikvision.com/ver20/XMLSchema"'

# A badly configured camera.
BAD = {
    "/ISAPI/System/deviceInfo": f"""<DeviceInfo {NS}><deviceName>Cam</deviceName>
        <model>DS-2CD2032-I</model><serialNumber>X1</serialNumber>
        <firmwareVersion>V5.4.0</firmwareVersion>
        <firmwareReleasedDate>build 160530</firmwareReleasedDate>
        <deviceType>IPCamera</deviceType></DeviceInfo>""",
    "/ISAPI/System/Network/UPnP": f"<UPnP {NS}><enabled>true</enabled></UPnP>",
    "/ISAPI/System/Network/EZVIZ": f"""<EZVIZ {NS}><enabled>true</enabled>
        <registerStatus>true</registerStatus><verificationCode>ABCDEF</verificationCode></EZVIZ>""",
    "/ISAPI/Security/adminAccesses": f"""<AdminAccessProtocolList {NS}>
        <AdminAccessProtocol><protocol>HTTP</protocol><enabled>true</enabled><portNo>80</portNo></AdminAccessProtocol>
        <AdminAccessProtocol><protocol>HTTPS</protocol><enabled>false</enabled><portNo>443</portNo></AdminAccessProtocol>
        <AdminAccessProtocol><protocol>RTSP</protocol><enabled>true</enabled><portNo>554</portNo></AdminAccessProtocol>
        </AdminAccessProtocolList>""",
    "/ISAPI/System/Network/telnetd": f"<Telnetd {NS}><enabled>true</enabled></Telnetd>",
    "/ISAPI/System/Network/ssh": f"<SSH {NS}><enabled>true</enabled></SSH>",
    "/ISAPI/System/Network/Integrate": f"""<Integrate {NS}><CGI><enable>true</enable></CGI>
        <ONVIF><enable>true</enable></ONVIF></Integrate>""",
    "/ISAPI/Security/illegalLoginLock": f"<IllegalLoginLock {NS}><enabled>false</enabled></IllegalLoginLock>",
    "/ISAPI/Security/webCertificate": f"<CertificateInfo {NS}><certificateType>digest/basic</certificateType></CertificateInfo>",
    "/ISAPI/Security/RTSPCertificate": f"<RTSPCertificate {NS}><certificateType>basic</certificateType></RTSPCertificate>",
    "/ISAPI/Security/users": f"""<UserList {NS}><User><userName>admin</userName></User>
        <User><userName>old</userName></User></UserList>""",
    "/ISAPI/System/time": f"<Time {NS}><timeMode>manual</timeMode></Time>",
}

# A well configured camera.
GOOD = {
    "/ISAPI/System/deviceInfo": f"""<DeviceInfo {NS}><model>DS-2CD2143G2-I</model>
        <firmwareVersion>V5.7.15</firmwareVersion>
        <firmwareReleasedDate>build 250801</firmwareReleasedDate></DeviceInfo>""",
    "/ISAPI/System/Network/UPnP": f"<UPnP {NS}><enabled>false</enabled></UPnP>",
    "/ISAPI/System/Network/EZVIZ": f"""<EZVIZ {NS}><enabled>true</enabled>
        <verificationCode>KQZTWM</verificationCode></EZVIZ>""",
    "/ISAPI/Security/adminAccesses": f"""<AdminAccessProtocolList {NS}>
        <AdminAccessProtocol><protocol>HTTPS</protocol><enabled>true</enabled><portNo>443</portNo></AdminAccessProtocol>
        </AdminAccessProtocolList>""",
    "/ISAPI/System/Network/ssh": f"<SSH {NS}><enabled>false</enabled></SSH>",
    "/ISAPI/Security/illegalLoginLock": f"""<IllegalLoginLock {NS}><enabled>true</enabled>
        <maxIllegalLoginTimes>5</maxIllegalLoginTimes></IllegalLoginLock>""",
    "/ISAPI/Security/RTSPCertificate": f"<RTSPCertificate {NS}><certificateType>digest</certificateType></RTSPCertificate>",
    "/ISAPI/System/time": f"<Time {NS}><timeMode>NTP</timeMode></Time>",
}


class FakeClient:
    def __init__(self, responses):
        self.responses = responses

    def get_xml(self, path):
        body = self.responses.get(path)
        return None if body is None else strip_ns(ET.fromstring(body))


def by_id(findings):
    return {f.id: f for f in findings}


class ChecksTest(unittest.TestCase):
    def test_bad_device_flags_problems(self):
        f = by_id(checks.run_all(FakeClient(BAD), "12345"))
        self.assertEqual(f["CVE-2021-36260"].severity, "HIGH")
        self.assertEqual(f["CVE-2017-7921"].severity, "HIGH")
        self.assertEqual(f["upnp"].severity, "HIGH")
        self.assertEqual(f["telnet"].severity, "HIGH")
        self.assertEqual(f["password"].severity, "HIGH")
        self.assertEqual(f["verification-code"].severity, "MEDIUM")
        self.assertEqual(f["https"].severity, "MEDIUM")
        self.assertEqual(f["ssh"].severity, "MEDIUM")
        self.assertEqual(f["lockout"].severity, "MEDIUM")
        self.assertEqual(f["auth-web"].severity, "MEDIUM")
        self.assertEqual(f["auth-rtsp"].severity, "MEDIUM")
        self.assertEqual(f["ntp"].severity, "LOW")
        self.assertIn("cgi", f)
        self.assertIn("old", f["users"].title)

    def test_good_device_has_no_high_or_medium(self):
        findings = checks.run_all(FakeClient(GOOD), "Str0ng!Passw0rd")
        bad = [x for x in findings if x.severity in ("HIGH", "MEDIUM")]
        self.assertEqual(bad, [], bad)

    def test_results_sorted_by_severity(self):
        sev = [f.severity for f in checks.run_all(FakeClient(BAD), "x")]
        self.assertEqual(sev, sorted(sev, key=checks.SEVERITY_ORDER.index))

    def test_unsupported_endpoints_are_skipped(self):
        findings = checks.run_all(FakeClient({}))
        self.assertTrue(all(f.severity == "INFO" for f in findings))

    def test_old_firmware_flagged_by_age(self):
        resp = {"/ISAPI/System/deviceInfo": GOOD["/ISAPI/System/deviceInfo"]}
        f = by_id(checks.check_firmware(FakeClient(resp), today=date(2030, 1, 1)))
        self.assertEqual(f["firmware-age"].severity, "MEDIUM")

    def test_parse_build(self):
        self.assertEqual(checks.parse_build("build 210628"), date(2021, 6, 28))
        self.assertIsNone(checks.parse_build("unknown"))

    def test_password_strength(self):
        self.assertEqual(checks.check_password("admin12345")[0].severity, "HIGH")
        self.assertEqual(checks.check_password("abcdefgh")[0].severity, "MEDIUM")
        self.assertEqual(checks.check_password("Gr8-Camera-Pass")[0].severity, "PASS")


class FakeCamera(http.server.BaseHTTPRequestHandler):
    responses = BAD

    def do_GET(self):
        body = self.responses.get(self.path)
        if body is None:
            self.send_response(404)
            self.end_headers()
            return
        self.send_response(200)
        self.send_header("Content-Type", "application/xml")
        self.end_headers()
        self.wfile.write(body.encode())

    def log_message(self, *a):
        pass


class ClientTest(unittest.TestCase):
    def setUp(self):
        self.server = http.server.ThreadingHTTPServer(("127.0.0.1", 0), FakeCamera)
        self.port = self.server.server_address[1]
        threading.Thread(target=self.server.serve_forever, daemon=True).start()

    def tearDown(self):
        self.server.shutdown()
        self.server.server_close()

    def test_client_reads_xml_and_handles_404(self):
        c = IsapiClient("127.0.0.1", "admin", "pw", port=self.port)
        self.assertEqual(c.get_xml("/ISAPI/System/deviceInfo").findtext("model"), "DS-2CD2032-I")
        self.assertIsNone(c.get_xml("/ISAPI/nope"))

    def test_wrong_password_raises(self):
        class Reject(FakeCamera):
            def do_GET(self):
                self.send_response(401)
                self.send_header("WWW-Authenticate", 'Basic realm="cam"')
                self.end_headers()
        self.server.RequestHandlerClass = Reject
        c = IsapiClient("127.0.0.1", "admin", "pw", port=self.port)
        with self.assertRaises(AuthError):
            c.get_xml("/ISAPI/System/deviceInfo")

    def test_cli_end_to_end(self):
        import os
        os.environ["HIK_PASSWORD"] = "12345"
        try:
            buf = io.StringIO()
            with redirect_stdout(buf):
                code = main(["audit", "--host", "127.0.0.1", "--port", str(self.port), "--skip-ports"])
        finally:
            del os.environ["HIK_PASSWORD"]
        self.assertEqual(code, 2)
        self.assertIn("UPnP is on", buf.getvalue())


if __name__ == "__main__":
    unittest.main()
