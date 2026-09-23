"""
Tests for Module 2 act phase and explanation trace (Sivaranjanii M).
Run from the project root with:  python -m unittest discover tests -v
"""

import os
import sys
import unittest

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.append(os.path.join(ROOT, "src"))

from knowledge_base import KnowledgeBase, Fact
from inference_engine import ForwardChainingEngine
from explanation import ExplanationBuilder

POWERSHELL_DOC = [
    "process_created:powershell.exe",
    "command_line_contains:-EncodedCommand",
    "parent_process:winword.exe",
]


def make_engine(fact_strings):
    kb = KnowledgeBase()
    kb.load_rules(os.path.join(ROOT, "data", "rules.json"))
    kb.load_mitigations(os.path.join(ROOT, "data", "mitigations.json"))
    engine = ForwardChainingEngine(kb)
    engine.assert_observations(Fact.from_string(s) for s in fact_strings)
    return engine


class TestActPhase(unittest.TestCase):

    def test_fired_rule_asserts_conclusions(self):
        engine = make_engine(POWERSHELL_DOC)
        memory = engine.run()
        self.assertIn(Fact("technique_detected", "T1059.001"), memory)
        self.assertIn(Fact("tactic_detected", "Execution"), memory)

    def test_chaining_uses_derived_fact(self):
        engine = make_engine(POWERSHELL_DOC)
        engine.run()
        fired = [e["rule_id"] for e in engine.get_trace()]
        self.assertEqual(fired, ["R001", "R018"])  # R018 needs R001's conclusion

    def test_terminates_by_quiescence(self):
        engine = make_engine(POWERSHELL_DOC)
        engine.run()
        self.assertTrue(engine.terminated)
        self.assertEqual(engine.termination_reason, "quiescence")

    def test_no_observations_fires_nothing(self):
        engine = make_engine([])
        engine.run()
        self.assertEqual(engine.get_trace(), [])
        self.assertEqual(engine.termination_reason, "quiescence")

    def test_each_rule_fires_once(self):
        engine = make_engine(POWERSHELL_DOC)
        engine.run()
        ids = [e["rule_id"] for e in engine.get_trace()]
        self.assertEqual(len(ids), len(set(ids)))

    def test_known_conclusion_does_not_stop_engine(self):
        # Conclusion already in memory before R001 fires: engine must
        # still record R001 and carry on to R018.
        engine = make_engine(POWERSHELL_DOC + ["technique_detected:T1059.001"])
        engine.run()
        fired = [e["rule_id"] for e in engine.get_trace()]
        self.assertIn("R001", fired)
        self.assertIn("R018", fired)

    def test_cycle_limit_guard(self):
        engine = make_engine(POWERSHELL_DOC)
        engine.run(max_cycles=1)
        self.assertEqual(engine.termination_reason, "cycle_limit")
        self.assertEqual(len(engine.get_trace()), 1)


class TestExplanation(unittest.TestCase):

    def test_explain_lists_rule_and_observed_facts(self):
        engine = make_engine(POWERSHELL_DOC)
        engine.run()
        text = ExplanationBuilder(engine).explain("T1059.001")
        self.assertIn("R001", text)
        for fact in POWERSHELL_DOC:
            self.assertIn(f"[observed] {fact}", text)

    def test_explain_follows_chain(self):
        engine = make_engine(POWERSHELL_DOC)
        engine.run()
        text = ExplanationBuilder(engine).explain("T1566.001")
        self.assertIn("[derived by R001]", text)
        self.assertIn("R018", text)

    def test_why_not_shows_missing_condition(self):
        engine = make_engine(["failed_login_count_exceeds:5", "same_source_ip:true"])
        engine.run()
        text = ExplanationBuilder(engine).why_not("T1110.001")
        self.assertIn("[MISSING] time_window_minutes:10", text)


if __name__ == "__main__":
    unittest.main()