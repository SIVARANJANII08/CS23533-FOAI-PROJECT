"""
Tests for the input layer, CLI menu and report format (Sivaranjanii M).
Run from the project root with:  python -m unittest discover tests -v
"""

import os
import sys
import tempfile
import unittest

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.append(os.path.join(ROOT, "src"))

from knowledge_base import KnowledgeBase
from input_parser import (
    parse_fact_lines, parse_log_lines, parse_file, list_samples, _contains_token,
)
from cli import NavigatorCLI, analyse
import report


def load_kb():
    kb = KnowledgeBase()
    kb.load_rules(os.path.join(ROOT, "data", "rules.json"))
    kb.load_mitigations(os.path.join(ROOT, "data", "mitigations.json"))
    return kb


KB = load_kb()


def detected_ids(parse_result):
    _, data = analyse(KB, parse_result)
    return [d["technique_id"] for d in data["detected"]]


class TestFactFiles(unittest.TestCase):

    def test_comments_blank_lines_and_duplicates(self):
        r = parse_fact_lines(
            ["# heading", "", "process_created:cmd.exe",
             "process_created:cmd.exe  # again", "  "],
            knowledge_base=KB,
        )
        self.assertEqual(r.fact_strings(), ["process_created:cmd.exe"])
        self.assertEqual(r.origins["process_created:cmd.exe"], [3, 4])
        self.assertEqual(r.warnings, [])

    def test_malformed_lines_are_warned_not_fatal(self):
        r = parse_fact_lines(["no colon here", "attr:", ":value", "same_source_ip:true"],
                             knowledge_base=KB)
        self.assertEqual(r.fact_strings(), ["same_source_ip:true"])
        self.assertEqual(len(r.warnings), 3)
        self.assertTrue(r.warnings[0].startswith("line 1:"))

    def test_unknown_attribute_is_kept_with_warning(self):
        r = parse_fact_lines(["user_mood:suspicious"], knowledge_base=KB)
        self.assertEqual(len(r), 1)
        self.assertIn("no rule uses", r.warnings[0])


class TestLogParsing(unittest.TestCase):

    def test_process_create_event(self):
        line = ('2026-10-14 09:12:07 EventType=ProcessCreate '
                'Image=C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe '
                'ParentImage="C:\\Program Files\\Microsoft Office\\WINWORD.EXE" '
                'CommandLine="powershell.exe -NoP -EncodedCommand SQBF"')
        r = parse_log_lines([line], knowledge_base=KB)
        self.assertEqual(
            set(r.fact_strings()),
            {"process_created:powershell.exe", "parent_process:winword.exe",
             "command_line_contains:-EncodedCommand"},
        )

    def test_token_match_respects_word_edges(self):
        self.assertTrue(_contains_token("cmd.exe /c whoami", "/c"))
        self.assertFalse(_contains_token("schtasks /create /tn x", "/c"))
        self.assertTrue(_contains_token("[Convert]::FromBase64String($s)", "FromBase64String"))

    def test_image_on_non_process_event_is_not_process_created(self):
        r = parse_log_lines(
            ["2026-10-14 09:00:00 EventType=NetworkConnect Image=C:\\x\\powershell.exe"],
            knowledge_base=KB,
        )
        self.assertEqual(len(r), 0)
        self.assertEqual(r.no_facts, [1])

    def test_output_redirection(self):
        r = parse_log_lines(
            ['2026-10-14 09:00:00 EventType=ProcessCreate Image=C:\\systeminfo.exe '
             'CommandLine="systeminfo > out.txt"'],
            knowledge_base=KB,
        )
        self.assertIn("command_output_redirected:true", r.fact_strings())

    def _failures(self, count, seconds_apart, ip="203.0.113.45"):
        lines = []
        for i in range(count):
            total = i * seconds_apart
            lines.append(
                f"2026-10-14 02:{total // 60:02d}:{total % 60:02d} "
                f"EventType=LogonFailure User=admin SourceIp={ip}"
            )
        return lines

    def test_brute_force_needs_more_than_five(self):
        five = parse_log_lines(self._failures(5, 20), knowledge_base=KB)
        six = parse_log_lines(self._failures(6, 20), knowledge_base=KB)
        self.assertNotIn("T1110.001", detected_ids(five))
        self.assertIn("T1110.001", detected_ids(six))

    def test_brute_force_outside_window_is_ignored(self):
        slow = parse_log_lines(self._failures(6, 150), knowledge_base=KB)  # 12.5 minutes
        self.assertEqual(len(slow), 0)

    def test_unsupported_extension(self):
        with tempfile.NamedTemporaryFile("w", suffix=".csv", delete=False) as f:
            f.write("a,b\n")
        try:
            with self.assertRaises(ValueError):
                parse_file(f.name, KB)
        finally:
            os.remove(f.name)


class TestSamples(unittest.TestCase):

    EXPECTED = {
        "01_malicious_document.log": {"T1059.001", "T1566.001", "T1082"},
        "02_brute_force.log": {"T1110.001"},
        "03_persistence.facts": {"T1547.001", "T1136.001"},
        "04_credential_dump.log": {"T1003.001", "T1552.001"},
        "05_defense_evasion.facts": {"T1562.001"},
        "06_discovery_recon.log": {"T1083", "T1057", "T1018"},
        "07_benign_activity.facts": set(),
        "08_messy_input.facts": {"T1059.001", "T1566.001"},
    }

    def test_every_sample_gives_expected_techniques(self):
        samples = list_samples(os.path.join(ROOT, "samples"))
        self.assertEqual(len(samples), len(self.EXPECTED))
        for path in samples:
            name = os.path.basename(path)
            with self.subTest(sample=name):
                result = parse_file(path, KB)
                self.assertEqual(set(detected_ids(result)), self.EXPECTED[name])


class TestReport(unittest.TestCase):

    def setUp(self):
        result = parse_file(os.path.join(ROOT, "samples", "01_malicious_document.log"), KB)
        self.agent, self.data = analyse(KB, result)
        self.text = report.render(self.data)

    def test_all_sections_present(self):
        for heading in ("[1] SUMMARY", "[2] OBSERVED FACTS", "[3] DETECTED TECHNIQUES",
                        "[4] DETECTION CHAIN", "[5] WHY", "[6] RECOMMENDED MITIGATIONS",
                        "[7] NEAR-MISS"):
            self.assertIn(heading, self.text)

    def test_report_is_plain_ascii(self):
        self.text.encode("ascii")   # raises if a non-ASCII character slipped in

    def test_tactics_follow_attack_order(self):
        self.assertEqual(self.data["tactics"], ["Initial Access", "Execution", "Discovery"])

    def test_mitigations_are_merged_and_m9001_flagged(self):
        ids = [m["id"] for m in self.data["mitigations"]]
        self.assertEqual(len(ids), len(set(ids)))
        self.assertIn("M9001 *", self.text)

    def test_table_wraps_long_cells(self):
        lines = report.ascii_table(["A", "B"], [["x", "word " * 20]], [3, 20])
        self.assertTrue(all(len(line) == len(lines[0]) for line in lines))
        self.assertGreater(len(lines), 5)

    def test_save(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = report.save(self.text, os.path.join(tmp, "r.txt"))
            with open(path, encoding="utf-8") as f:
                self.assertIn("END OF REPORT", f.read())


class TestCLI(unittest.TestCase):

    def run_menu(self, answers):
        feed = iter(answers)
        output = []
        cli = NavigatorCLI(KB, ROOT, input_fn=lambda _: next(feed),
                           print_fn=lambda *a: output.append(" ".join(str(x) for x in a)))
        cli.reports_dir = tempfile.mkdtemp()
        cli.run()
        return cli, "\n".join(output)

    def test_sample_run_and_why_not(self):
        cli, out = self.run_menu(["1", "2", "5", "", "6", "T1566.001", "0"])
        self.assertIn("T1110.001", out)
        self.assertIn("T1566.001 - Phishing: Spearphishing Attachment was NOT concluded.", out)
        self.assertIn("Goodbye.", out)

    def test_manual_entry(self):
        cli, out = self.run_menu([
            "3", "process_created:tasklist.exe", "command_line_contains:/svc", "",
            "5", "", "0",
        ])
        self.assertEqual([d["technique_id"] for d in cli.data["detected"]], ["T1057"])

    def test_bad_choices_do_not_crash(self):
        cli, out = self.run_menu(["42", "6", "7", "5", "0"])
        self.assertIn("Please enter a number from the menu.", out)
        self.assertIn("Run an analysis first", out)
        self.assertIn("Load an input first", out)

    def test_end_of_input_exits_cleanly(self):
        def no_more(_):
            raise EOFError
        cli = NavigatorCLI(KB, ROOT, input_fn=no_more, print_fn=lambda *a: None)
        cli.run()   # should return, not raise


if __name__ == "__main__":
    unittest.main()
