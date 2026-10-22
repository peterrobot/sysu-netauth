import os
from pathlib import Path
import shutil
import subprocess
import sys
import tempfile
import unittest
import xml.etree.ElementTree as ET

ROOT = Path(__file__).resolve().parents[1]
PROTOTYPE = ROOT / "apps/rust/eap-peer"


class EapHostProfileTests(unittest.TestCase):
    def test_profile_uses_binary_config_and_never_caches_credentials(self):
        root = ET.parse(PROTOTYPE / "wired-profile.xml").getroot()
        ns = {
            "l": "http://www.microsoft.com/networking/LAN/profile/v1",
            "o": "http://www.microsoft.com/networking/OneX/v1",
            "h": "http://www.microsoft.com/provisioning/EapHostConfig",
            "e": "http://www.microsoft.com/provisioning/EapCommon",
        }
        self.assertEqual(root.findtext(".//l:OneXEnabled", namespaces=ns), "true")
        self.assertEqual(root.findtext(".//o:authMode", namespaces=ns), "machine")
        self.assertEqual(root.findtext(".//o:cacheUserData", namespaces=ns), "false")
        self.assertEqual(root.findtext(".//h:EapMethod/e:Type", namespaces=ns), "4")
        self.assertEqual(root.findtext(".//h:EapMethod/e:AuthorId", namespaces=ns), "32473")
        blob = bytes.fromhex(root.findtext(".//h:ConfigBlob", namespaces=ns))
        self.assertEqual(blob, b"SYSU-EAP-MD5-v1")
        self.assertIsNone(root.find(".//h:Config", ns))

    @unittest.skipUnless(
        sys.platform == "win32" and shutil.which("cl.exe") and shutil.which("cargo"),
        "requires a Windows SDK developer shell and a native Windows Rust host",
    )
    def test_dll_callbacks_match_sdk_and_exchange_packets(self):
        subprocess.run(["cargo", "build", "--locked", "-p", "sysu-netauth-eap-peer"], cwd=ROOT, check=True)
        target = Path(os.environ.get("CARGO_TARGET_DIR", ROOT / "target"))
        if not target.is_absolute():
            target = ROOT / target
        dll = target / "debug/sysu_netauth_eap_peer.dll"
        with tempfile.TemporaryDirectory(prefix="netauth eaphost checks ") as tmp:
            exe = Path(tmp) / "eaphost-peer-check.exe"
            subprocess.run([
                "cl.exe", "/nologo", "/W3", "/wd4191", "/TC",
                str(ROOT / "tests/fixtures/eaphost_peer.c"), f"/Fe{exe}",
            ], cwd=tmp, check=True)
            result = subprocess.run([str(exe), str(dll)], text=True, capture_output=True, timeout=30)
            self.assertEqual(result.returncode, 0, result.stdout + result.stderr)


if __name__ == "__main__":
    unittest.main()
