"""运行：python3 -m unittest test_ipcalc -v"""
import ipaddress
import subprocess
import sys
import unittest
from pathlib import Path

from ipcalc import analyze


class IPCalcTests(unittest.TestCase):
    def test_ipv4_reference(self):
        d = analyze("192.168.1.130/26")
        self.assertEqual(str(d["network"]), "192.168.1.128/26")
        self.assertEqual(str(d["first_host"]), "192.168.1.129")
        self.assertEqual(str(d["last_host"]), "192.168.1.190")
        self.assertEqual((d["total"], d["usable"]), (64, 62))

    def test_ipv6_reference(self):
        d = analyze("2001:db8::/48")
        self.assertEqual(d["total"], 1208925819614629174706176)
        self.assertEqual(str(d["last"]), "2001:db8:0:ffff:ffff:ffff:ffff:ffff")
        self.assertEqual(d["reverse_zone"], "0.0.0.0.8.b.d.0.1.0.0.2.ip6.arpa")

    def test_boundaries(self):
        for cidr, usable in [("0.0.0.0/0", 2**32 - 2),
                             ("192.0.2.0/31", 2), ("192.0.2.7/32", 1)]:
            with self.subTest(cidr=cidr):
                self.assertEqual(analyze(cidr)["usable"], usable)
        for cidr, count in [("::/0", 2**128), ("2001:db8::/127", 2),
                            ("ffff:ffff:ffff:ffff:ffff:ffff:ffff:ffff/128", 1)]:
            with self.subTest(cidr=cidr):
                self.assertEqual(analyze(cidr)["total"], count)

    def test_single_addresses_and_masks(self):
        self.assertEqual(analyze("192.0.2.7")["network"].prefixlen, 32)
        self.assertEqual(analyze("2001:db8::7")["network"].prefixlen, 128)
        self.assertEqual(analyze("192.168.1.130/255.255.255.192")["usable"], 62)
        self.assertEqual(analyze("::/0")["reverse_zone"], "ip6.arpa")
        self.assertIn("无单一", analyze("2001:db8::/65")["reverse_zone"])

    def test_all_prefixes_without_enumeration(self):
        for address, width in [("192.168.1.130", 32), ("2001:db8::abcd", 128)]:
            for prefix in range(width + 1):
                d = analyze(f"{address}/{prefix}")
                self.assertEqual(int(d["last"]) - int(d["first"]) + 1, 2**(width - prefix))
                self.assertIn(ipaddress.ip_address(address), d["network"])

    def test_invalid(self):
        for value in ["", "invalid", "999.1.1.1", "192.0.2.1/33", "::/129", "fe80::1%en0"]:
            with self.subTest(value=value), self.assertRaises(ValueError):
                analyze(value)

    def test_cli(self):
        script = str(Path(__file__).with_name("ipcalc.py"))
        result = subprocess.run([sys.executable, script, "192.168.1.130/26"], capture_output=True, text=True)
        self.assertEqual(result.returncode, 0)
        self.assertIn("192.168.1.129", result.stdout)
        self.assertNotIn("\033[", result.stdout)
        result = subprocess.run([sys.executable, script, "::/129"], capture_output=True, text=True)
        self.assertEqual(result.returncode, 2)
        self.assertNotIn("Traceback", result.stderr)


if __name__ == "__main__":
    unittest.main()
