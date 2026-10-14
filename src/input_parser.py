"""
Input Layer: Log Parser
MITRE ATT&CK Rule-Based Navigator

Owner: Sivaranjanii M

Turns an input file into the attribute:value facts the inference engine
works on. Two file formats are supported:

1. Fact files (.facts or .txt)
   One fact per line, written exactly as the rules expect them:

       # malicious Word document
       process_created:powershell.exe
       parent_process:winword.exe

   Blank lines and lines starting with # are ignored.

2. Event logs (.log)
   One event per line, a timestamp followed by key=value fields.
   Values with spaces go in double quotes:

       2026-10-14 09:12:03 EventType=ProcessCreate Image=C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe ParentImage=C:\\Program Files\\Microsoft Office\\winword.exe CommandLine="powershell.exe -EncodedCommand SQBFAFgA"

   Each field is turned into facts by fixed extraction rules (see
   FIELD_MAP and _facts_from_event). A field whose key is already a
   knowledge-base attribute, e.g. network_scan_detected=true, is passed
   through unchanged.

The parser never guesses. It only emits facts that a written extraction
rule produces, and it reports every line it could not use as a warning
with its line number instead of stopping.
"""

import os
import re
from datetime import datetime

try:
    from .knowledge_base import Fact
except ImportError:
    from knowledge_base import Fact


# ----------------------------------------------------------------------
# Extraction rules for .log files
# ----------------------------------------------------------------------

# Log field name -> fact attribute. The value is reduced to the file name
# (lower case) for fields that hold an executable path.
FIELD_MAP = {
    "Image": ("process_created", True),
    "ParentImage": ("parent_process", True),
    "TargetImage": ("process_access_target", True),
    "GrantedAccess": ("access_mask", False),
    "TargetObject": ("registry_key_modified", False),
}

PROCESS_CREATE_EVENT = "ProcessCreate"

# Attributes whose rule values are substrings to look for inside the
# CommandLine field, e.g. command_line_contains:-EncodedCommand.
COMMAND_LINE_ATTRIBUTE = "command_line_contains"

# Brute-force aggregation (feeds rule R007, T1110.001).
# More than FAILED_LOGIN_THRESHOLD failures from one source IP inside
# FAILED_LOGIN_WINDOW_MINUTES produce the three facts R007 needs.
FAILED_LOGIN_EVENT = "LogonFailure"
FAILED_LOGIN_THRESHOLD = 5
FAILED_LOGIN_WINDOW_MINUTES = 10

FIELD_PATTERN = re.compile(r'([A-Za-z_][\w]*)=("([^"]*)"|\S+)')

TIMESTAMP_FORMATS = ("%Y-%m-%d %H:%M:%S", "%Y-%m-%dT%H:%M:%S")

FACT_EXTENSIONS = (".facts", ".txt")
LOG_EXTENSIONS = (".log",)


class ParseResult:
    """
    What the parser hands to the rest of the system.

    facts      - Fact objects in the order they were first seen (no duplicates)
    origins    - fact string -> list of line numbers it came from
    warnings   - messages about lines that were skipped or look odd
    source     - file name, or "manual entry" / "built-in demo"
    lines_read - number of non-empty, non-comment lines processed
    no_facts   - log line numbers that parsed fine but matched no
                 extraction rule (ordinary activity, not an error)
    """

    def __init__(self, source):
        self.source = source
        self.facts = []
        self.origins = {}
        self.warnings = []
        self.lines_read = 0
        self.no_facts = []

    def add(self, fact, line_no=None):
        key = str(fact)
        if key not in self.origins:
            self.facts.append(fact)
            self.origins[key] = []
        if line_no is not None and line_no not in self.origins[key]:
            self.origins[key].append(line_no)

    def warn(self, line_no, message):
        prefix = f"line {line_no}: " if line_no is not None else ""
        self.warnings.append(prefix + message)

    def fact_strings(self):
        return [str(f) for f in self.facts]

    def __len__(self):
        return len(self.facts)


# ----------------------------------------------------------------------
# Helpers
# ----------------------------------------------------------------------

def kb_vocabulary(knowledge_base):
    """
    attribute -> set of values used anywhere in the rule conditions.
    Used to check facts against the knowledge base and to know which
    substrings to look for in a command line.
    """

    vocab = {}
    if knowledge_base is None:
        return vocab
    for rule in knowledge_base.rules:
        for condition in rule.conditions:
            vocab.setdefault(condition.attribute, set()).add(condition.value)
    return vocab


def _exe_name(path):
    """C:\\Windows\\System32\\cmd.exe -> cmd.exe"""

    return re.split(r"[\\/]", path.strip())[-1].lower()


def _contains_token(text, token):
    """
    Case-insensitive search for token in text, where the match may not
    sit inside a longer word. This stops "/c" matching inside "/create".
    """

    pattern = (
        r"(?<![A-Za-z0-9])" + re.escape(token) + r"(?![A-Za-z0-9])"
    )
    return re.search(pattern, text, flags=re.IGNORECASE) is not None


def _parse_timestamp(line):
    """Return (datetime or None, rest of line)."""

    head = line[:19]   # "2026-10-14 09:12:03" is 19 characters
    for fmt in TIMESTAMP_FORMATS:
        try:
            return datetime.strptime(head, fmt), line[19:].strip()
        except ValueError:
            continue
    return None, line


def _check_against_kb(result, fact, line_no, vocab):
    """Warn when a fact uses an attribute no rule ever looks at."""

    if vocab and fact.attribute not in vocab:
        result.warn(
            line_no,
            f"'{fact}' kept, but no rule uses the attribute "
            f"'{fact.attribute}'",
        )


# ----------------------------------------------------------------------
# Fact files
# ----------------------------------------------------------------------

def parse_fact_lines(lines, source="manual entry", knowledge_base=None):
    """Parse attribute:value lines. Used for .facts files and manual entry."""

    result = ParseResult(source)
    vocab = kb_vocabulary(knowledge_base)

    for line_no, raw in enumerate(lines, start=1):
        line = raw.strip()
        if not line or line.startswith("#"):
            continue

        # allow a trailing comment: process_created:cmd.exe  # note
        if " #" in line:
            line = line.split(" #", 1)[0].strip()

        result.lines_read += 1

        try:
            fact = Fact.from_string(line)
        except ValueError:
            result.warn(
                line_no,
                f"skipped '{line}' (expected attribute:value)",
            )
            continue

        _check_against_kb(result, fact, line_no, vocab)
        result.add(fact, line_no)

    return result


# ----------------------------------------------------------------------
# Event logs
# ----------------------------------------------------------------------

def _facts_from_event(fields, vocab):
    """
    Apply the extraction rules to one event's fields.
    Returns a list of (Fact, note) pairs.
    """

    facts = []

    for key, value in fields.items():

        # Rule 1: mapped Sysmon-style fields. Image only means "a process
        # was created" on a ProcessCreate event; on other events it is
        # just the process doing the action.
        if key == "Image" and fields.get("EventType", PROCESS_CREATE_EVENT) != PROCESS_CREATE_EVENT:
            continue
        if key in FIELD_MAP:
            attribute, is_path = FIELD_MAP[key]
            facts.append(Fact(attribute, _exe_name(value) if is_path else value))
            continue

        # Rule 2: CommandLine -> every known command_line_contains value
        # that appears in it, plus output redirection
        if key == "CommandLine":
            for token in sorted(vocab.get(COMMAND_LINE_ATTRIBUTE, ())):
                if _contains_token(value, token):
                    facts.append(Fact(COMMAND_LINE_ATTRIBUTE, token))
            if ">" in value:
                facts.append(Fact("command_output_redirected", "true"))
            continue

        # Rule 3: field already named like a knowledge-base attribute
        if key in vocab:
            facts.append(Fact(key, value))
            continue

    return facts


def _aggregate_failed_logins(events, result):
    """
    Rule 4: brute-force aggregation.

    Groups LogonFailure events by SourceIp. If any IP has more than
    FAILED_LOGIN_THRESHOLD failures inside a FAILED_LOGIN_WINDOW_MINUTES
    window, the facts for R007 are asserted.
    """

    by_ip = {}
    for line_no, ts, fields in events:
        if fields.get("EventType") != FAILED_LOGIN_EVENT:
            continue
        ip = fields.get("SourceIp")
        if ip is None or ts is None:
            result.warn(
                line_no,
                "LogonFailure event needs a timestamp and SourceIp; ignored",
            )
            continue
        by_ip.setdefault(ip, []).append((ts, line_no))

    for ip, attempts in by_ip.items():
        attempts.sort()
        # sliding window over the sorted attempts
        start = 0
        for end in range(len(attempts)):
            while (
                (attempts[end][0] - attempts[start][0]).total_seconds()
                > FAILED_LOGIN_WINDOW_MINUTES * 60
            ):
                start += 1
            count = end - start + 1
            if count > FAILED_LOGIN_THRESHOLD:
                lines = [ln for _, ln in attempts[start:end + 1]]
                for fact in (
                    Fact("failed_login_count_exceeds", str(FAILED_LOGIN_THRESHOLD)),
                    Fact("same_source_ip", "true"),
                    Fact("time_window_minutes", str(FAILED_LOGIN_WINDOW_MINUTES)),
                ):
                    for ln in lines:
                        result.add(fact, ln)
                break


def parse_log_lines(lines, source="event log", knowledge_base=None):
    """Parse key=value event log lines."""

    result = ParseResult(source)
    vocab = kb_vocabulary(knowledge_base)
    events = []

    for line_no, raw in enumerate(lines, start=1):
        line = raw.strip()
        if not line or line.startswith("#"):
            continue

        result.lines_read += 1
        ts, rest = _parse_timestamp(line)

        fields = {
            m.group(1): (m.group(3) if m.group(3) is not None else m.group(2))
            for m in FIELD_PATTERN.finditer(rest)
        }

        if not fields:
            result.warn(line_no, "no key=value fields found; line skipped")
            continue

        events.append((line_no, ts, fields))

        extracted = _facts_from_event(fields, vocab)
        for fact in extracted:
            result.add(fact, line_no)

        if not extracted and fields.get("EventType") != FAILED_LOGIN_EVENT:
            result.no_facts.append(line_no)

    _aggregate_failed_logins(events, result)
    return result


# ----------------------------------------------------------------------
# Entry point
# ----------------------------------------------------------------------

def parse_file(path, knowledge_base=None):
    """
    Read an input file and return a ParseResult.
    The format is chosen by file extension.
    """

    if not os.path.isfile(path):
        raise FileNotFoundError(f"Input file not found: {path}")

    with open(path, "r", encoding="utf-8-sig") as handle:
        lines = handle.readlines()

    name = os.path.basename(path)
    ext = os.path.splitext(path)[1].lower()

    if ext in LOG_EXTENSIONS:
        return parse_log_lines(lines, source=name, knowledge_base=knowledge_base)
    if ext in FACT_EXTENSIONS:
        return parse_fact_lines(lines, source=name, knowledge_base=knowledge_base)

    raise ValueError(
        f"Unsupported file type '{ext}'. "
        f"Use {', '.join(FACT_EXTENSIONS + LOG_EXTENSIONS)}."
    )


def list_samples(folder):
    """Sample input files in a folder, sorted by name."""

    if not os.path.isdir(folder):
        return []
    return sorted(
        os.path.join(folder, f)
        for f in os.listdir(folder)
        if f.lower().endswith(FACT_EXTENSIONS + LOG_EXTENSIONS)
    )


def describe_sample(path):
    """First comment line of a sample file, used as its menu description."""

    try:
        with open(path, "r", encoding="utf-8-sig") as handle:
            for line in handle:
                line = line.strip()
                if line.startswith("#"):
                    return line.lstrip("#").strip()
                if line:
                    break
    except OSError:
        pass
    return ""
