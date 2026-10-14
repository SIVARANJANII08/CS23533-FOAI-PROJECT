"""
Input Layer: Interactive CLI Menu
MITRE ATT&CK Rule-Based Navigator

Owner: Sivaranjanii M

A numbered text menu for running the navigator without editing code.
The user picks an input (sample scenario, their own file, or facts typed
by hand), runs the analysis, and can then ask follow-up questions:
why a technique was NOT detected, save the report, or draw the chain.

input_fn and print_fn can be swapped out, which is how the tests drive
the menu with scripted answers.
"""

import os
from datetime import datetime

try:
    from .agent import Agent
    from .input_parser import (
        parse_file, parse_fact_lines, list_samples, describe_sample,
    )
    from . import report
    from . import visualize
except ImportError:
    from agent import Agent
    from input_parser import (
        parse_file, parse_fact_lines, list_samples, describe_sample,
    )
    import report
    import visualize


def analyse(knowledge_base, parse_result):
    """Run one full pass of the agent. Returns (agent, report data)."""

    agent = Agent(knowledge_base)
    agent.process(parse_result.facts)
    data = report.collect(agent, knowledge_base, parse_result)
    return agent, data


def _safe_name(text):
    keep = "".join(ch if ch.isalnum() or ch in "-_" else "_" for ch in text)
    return keep.strip("_") or "input"


class NavigatorCLI:

    MENU = [
        ("1", "Load a sample scenario"),
        ("2", "Load your own input file (.log / .facts / .txt)"),
        ("3", "Type facts in by hand"),
        ("4", "View current facts"),
        ("5", "Run analysis and show report"),
        ("6", "Why not? Explain a technique that was not detected"),
        ("7", "Save last report to a text file"),
        ("8", "Draw detection chain chart (matplotlib)"),
        ("9", "Browse the knowledge base rules"),
        ("0", "Exit"),
    ]

    def __init__(self, knowledge_base, root, input_fn=input, print_fn=print):
        self.kb = knowledge_base
        self.root = root
        self.samples_dir = os.path.join(root, "samples")
        self.reports_dir = os.path.join(root, "reports")
        self.ask = input_fn
        self.say = print_fn
        self.current = None      # ParseResult waiting to be analysed
        self.agent = None        # agent from the last run
        self.data = None         # report data from the last run
        self.text = None         # report text from the last run

    # -- small helpers -------------------------------------------------

    def _prompt(self, message):
        try:
            return self.ask(message).strip()
        except EOFError:
            return "0"

    def _status_line(self):
        if self.current is None:
            return "  Current input: none loaded"
        state = "analysed" if self.data and self.data["source"] == self.current.source else "not analysed yet"
        return (f"  Current input: {self.current.source} "
                f"({len(self.current)} facts, {state})")

    def _need_run(self):
        if self.agent is None:
            self.say("\n  Run an analysis first (option 5).")
            return False
        return True

    def _set_input(self, result):
        self.current = result
        self.say(f"\n  Loaded {len(result)} fact(s) from {result.source}.")
        for w in result.warnings:
            self.say(f"  ! {w}")
        if len(result) == 0:
            self.say("  No usable facts found, so nothing can be detected.")

    # -- menu actions --------------------------------------------------

    def load_sample(self):
        samples = list_samples(self.samples_dir)
        if not samples:
            self.say(f"\n  No sample files found in {self.samples_dir}")
            return
        self.say("\n  Sample scenarios:")
        for i, path in enumerate(samples, start=1):
            name = os.path.basename(path)
            self.say(f"   {i}. {name:<28} {describe_sample(path)}")
        choice = self._prompt("\n  Pick a number (Enter to cancel): ")
        if not choice:
            return
        if not choice.isdigit() or not 1 <= int(choice) <= len(samples):
            self.say("  Not a valid number.")
            return
        self._set_input(parse_file(samples[int(choice) - 1], self.kb))

    def load_file(self):
        path = self._prompt("\n  Path to the input file: ").strip('"').strip("'")
        if not path:
            return
        if not os.path.isabs(path) and not os.path.exists(path):
            path = os.path.join(self.root, path)
        try:
            self._set_input(parse_file(path, self.kb))
        except (FileNotFoundError, ValueError) as err:
            self.say(f"  Could not load: {err}")

    def enter_facts(self):
        self.say("\n  Type one fact per line as attribute:value, "
                 "e.g. process_created:powershell.exe")
        self.say("  Press Enter on an empty line when you are done.")
        lines = []
        while True:
            line = self._prompt("  fact> ")
            if not line or line == "0":
                break
            lines.append(line)
        if not lines:
            self.say("  No facts entered.")
            return
        self._set_input(parse_fact_lines(lines, source="manual entry", knowledge_base=self.kb))

    def show_facts(self):
        if self.current is None:
            self.say("\n  Nothing loaded yet.")
            return
        self.say(f"\n  Facts from {self.current.source}:")
        for i, fact in enumerate(self.current.facts, start=1):
            self.say(f"   {i:>2}. {fact}")

    def run_analysis(self):
        if self.current is None:
            self.say("\n  Load an input first (options 1-3).")
            return
        self.agent, self.data = analyse(self.kb, self.current)
        self.text = report.render(self.data)
        self.say("\n" + self.text)
        # pause so the report stays on screen instead of being pushed
        # up by the menu straight away
        self._prompt("\n  Report finished. Scroll up to read it all. "
                     "Press Enter to return to the menu...")

    def why_not(self):
        if not self._need_run():
            return
        detected = {d["technique_id"] for d in self.data["detected"]}
        hints = [n["technique_id"] for n in self.data["near_misses"]]
        if hints:
            self.say(f"\n  Near misses from the last run: {', '.join(hints)}")
        technique = self._prompt("  Technique ID (e.g. T1110.001): ").upper()
        if not technique:
            return
        if technique in detected:
            self.say("\n" + self.agent.explainer.explain(technique))
        else:
            self.say("\n" + self.agent.explainer.why_not(technique))

    def save_report(self):
        if not self._need_run():
            return
        os.makedirs(self.reports_dir, exist_ok=True)
        stamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        default = os.path.join(
            self.reports_dir, f"report_{_safe_name(self.data['source'])}_{stamp}.txt"
        )
        path = self._prompt(f"\n  Save as [{os.path.relpath(default, self.root)}]: ") or default
        if not os.path.isabs(path):
            path = os.path.join(self.root, path)
        report.save(self.text, path)
        self.say(f"  Report saved to {path}")

    def draw_chart(self):
        if not self._need_run():
            return
        if not visualize.matplotlib_available():
            self.say("\n  matplotlib is not installed. Install it with:  pip install matplotlib")
            return
        path = os.path.join(
            self.reports_dir, f"chain_{_safe_name(self.data['source'])}.png"
        )
        show = self._prompt("\n  Open the chart in a window as well? (y/N): ").lower() == "y"
        try:
            visualize.draw_chain(self.data, path, show=show)
        except ValueError as err:
            self.say(f"  {err}")
            return
        self.say(f"  Chart saved to {path}")

    def browse_rules(self):
        rows = [
            [r.rule_id, r.technique_id, r.technique_name, r.tactic,
             r.severity.upper(), len(r.conditions)]
            for r in self.kb.rules
        ]
        self.say("")
        for line in report.ascii_table(
            ["Rule", "Technique", "Name", "Tactic", "Severity", "Conds"],
            rows, [4, 10, 40, 17, 8, 5],
        ):
            self.say("  " + line)
        rule_id = self._prompt("\n  Rule ID to see its conditions (Enter to go back): ").upper()
        rule = next((r for r in self.kb.rules if r.rule_id == rule_id), None)
        if rule_id and rule is None:
            self.say("  No such rule.")
        elif rule:
            self.say(f"\n  {rule}")
            self.say(f"  Tactic: {rule.tactic} | Severity: {rule.severity}")
            self.say("  IF all of:")
            for c in rule.conditions:
                self.say(f"     - {c}")
            self.say(f"  THEN technique_detected:{rule.technique_id}, "
                     f"tactic_detected:{rule.tactic}")
            self.say(f"  Mitigations: {', '.join(rule.mitigation_ids) or 'none'}")

    # -- main loop -----------------------------------------------------

    def run(self):
        actions = {
            "1": self.load_sample, "2": self.load_file, "3": self.enter_facts,
            "4": self.show_facts, "5": self.run_analysis, "6": self.why_not,
            "7": self.save_report, "8": self.draw_chart, "9": self.browse_rules,
        }
        self.say("=" * 60)
        self.say("   MITRE ATT&CK Rule-Based Navigator")
        self.say("=" * 60)
        self.say("  " + self.kb.summary())

        while True:
            self.say("")
            self.say(self._status_line())
            self.say("-" * 60)
            for key, label in self.MENU:
                self.say(f"   {key}. {label}")
            choice = self._prompt("\n  Choose an option: ")
            if choice == "0":
                self.say("\n  Goodbye.")
                return
            action = actions.get(choice)
            if action is None:
                self.say("  Please enter a number from the menu.")
                continue
            try:
                action()
            except KeyboardInterrupt:
                self.say("\n  Cancelled.")
