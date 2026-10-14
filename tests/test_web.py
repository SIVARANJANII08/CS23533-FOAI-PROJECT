"""
Tests for the web interface (Sivaranjanii M).
Skipped automatically if Flask is not installed.
"""

import io
import os
import sys
import unittest

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, ROOT)

try:
    import app as web
    HAVE_FLASK = True
except ImportError:
    HAVE_FLASK = False


@unittest.skipUnless(HAVE_FLASK, "Flask not installed")
class TestWeb(unittest.TestCase):

    def setUp(self):
        self.client = web.app.test_client()

    def test_home_page_lists_samples(self):
        page = self.client.get("/").get_data(as_text=True)
        self.assertIn("01_malicious_document.log", page)
        self.assertIn("Loaded 18 rules", page)

    def test_sample_shows_techniques_and_mitigations(self):
        r = self.client.post("/analyse", data={"mode": "sample", "sample": "01_malicious_document.log"})
        page = r.get_data(as_text=True)
        self.assertEqual(r.status_code, 200)
        for text in ("T1059.001", "T1566.001", "T1082", "Recommended mitigations", "M1049", "M9001"):
            self.assertIn(text, page)

    def test_several_typed_facts(self):
        facts = "process_created:tasklist.exe\ncommand_line_contains:/svc\nprocess_created:cmd.exe"
        page = self.client.post("/analyse", data={"mode": "manual", "facts": facts}).get_data(as_text=True)
        self.assertIn("T1057", page)

    def test_upload_log(self):
        with open(os.path.join(ROOT, "samples", "02_brute_force.log"), "rb") as f:
            data = {"mode": "upload", "upload": (io.BytesIO(f.read()), "02_brute_force.log")}
        page = self.client.post("/analyse", data=data, content_type="multipart/form-data").get_data(as_text=True)
        self.assertIn("T1110.001", page)

    def test_why_not(self):
        facts = "failed_login_count_exceeds:5\nsame_source_ip:true"
        page = self.client.post("/analyse", data={
            "mode": "rerun", "facts": facts, "source": "x", "why_not": "T1110.001",
        }).get_data(as_text=True)
        self.assertIn("was NOT concluded", page)
        self.assertIn("[MISSING] time_window_minutes:10", page)

    def test_empty_and_bad_input(self):
        self.assertEqual(self.client.post("/analyse", data={"mode": "manual", "facts": ""}).status_code, 400)
        self.assertEqual(self.client.post("/analyse", data={"mode": "sample", "sample": "../app.py"}).status_code, 400)

    def test_rules_page(self):
        page = self.client.get("/rules").get_data(as_text=True)
        self.assertIn("R018", page)


if __name__ == "__main__":
    unittest.main()
