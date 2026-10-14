# MITRE ATT&CK Rule-Based Navigator

A classical AI expert system that maps observed system behaviours to MITRE ATT&CK
techniques and recommends mitigations. Every conclusion can be traced back to the
rule that produced it and the facts that satisfied that rule.

AI Foundations Mini-Project (CS23533)
Supervisor: Dr. S. Bhuvana

## Team

| Member | Roll No | Owns |
|---|---|---|
| Pranathee H | 241901078 | `src/`: match phase, best-first search, agent |
| Sivaranjanii M | 241901109 | `data/`: knowledge base, rules, mitigations; act phase and explanation trace (Module 2); input layer, CLI menu, report format, sample inputs and documentation (Module 4) |

Both members work in the same GitHub repository with file-level ownership, so
modules can be built in parallel against a shared data schema.

## Approach

The system is built entirely from symbolic AI techniques. In a security setting an
analyst needs to see why a technique was flagged before acting on it. A production
rule makes that reasoning explicit: the rule ID, its conditions and the matching
facts are all visible in the explanation trace.

| Module | AI technique |
|---|---|
| 1. Knowledge base and fact representation | IF-THEN production rules |
| 2. Forward chaining inference engine | Forward chaining (match, act, termination) |
| 3. Best-first search and heuristic prioritisation | Best-first search, heuristic = matched ÷ total conditions |
| 4. Agent integration, interface and testing | Goal-based intelligent agent, with a log parser, menu interface and tabular report |

## Knowledge base

The knowledge base holds 18 rules covering 6 ATT&CK tactics: Initial Access,
Execution, Persistence, Credential Access, Defense Evasion and Discovery. It links
to 18 mitigations.

Facts are stored in working memory as `attribute:value` strings.

Each rule in `data/rules.json` has these fields:

| Field | Meaning |
|---|---|
| `rule_id` | Unique rule identifier, e.g. `R001` |
| `technique_id` | ATT&CK technique ID |
| `technique_name` | ATT&CK technique name |
| `tactic` | ATT&CK tactic the technique belongs to |
| `severity` | Severity rating for prioritisation |
| `conditions` | List of facts that must all be present for the rule to fire |
| `mitigation_ids` | Links into `data/mitigations.json` |

Rules can chain. When a rule fires, its conclusion is asserted into working memory
and can satisfy conditions in later rules. For example, R018 (T1566.001,
Spearphishing Attachment) chains off R001.

### Notes on the data

M9001 is a team-defined code, not an official ATT&CK mitigation. ATT&CK lists no
preventive mitigations for Discovery techniques, so M9001 carries detection-focused
guidance for those rules instead.

Rule conditions are illustrative observables taken from the Detection and Procedure
Examples sections of each ATT&CK technique page. They show how the reasoning works
and have not been validated as production detection logic.

## Running the website (local host)

```
pip install -r requirements.txt
python app.py
```

Then open http://127.0.0.1:5000 in a browser. Press Ctrl+C in the terminal to stop it.
The website runs only on your own computer. It uses the same rule engine as the
command-line version, so both give the same results.

| Page | What it does |
|---|---|
| Analyse (home) | Pick a sample, type several facts (one per line) or upload a `.log` / `.facts` / `.txt` file |
| Report | Summary tiles, tactics reached, detected techniques, detection chain with chart, Why explanation, mitigations, near misses, a "why not?" box and the observed facts |
| Knowledge base | All 18 rules with their IF conditions, THEN conclusions and mitigations |

## Running it

The navigator is a command-line program. There is no website or server: it runs in
a terminal (Command Prompt, PowerShell or the VS Code terminal) with Python 3.9 or
later. The only optional extra is matplotlib, used for the detection chain chart.

```
pip install matplotlib          # optional, only for the chart
python main.py                  # interactive menu
```

Other ways to run it:

| Command | What it does |
|---|---|
| `python main.py` | Opens the interactive menu |
| `python main.py --list-samples` | Lists the sample input files |
| `python main.py --file samples/02_brute_force.log` | Analyses one file and prints the report |
| `python main.py --file samples/01_malicious_document.log --save reports/r1.txt --chart reports/r1.png` | Same, and also saves the report and chart |
| `python main.py --demo` | Runs the original hard-coded scenario (Word document launching PowerShell) |
| `python -m unittest discover tests -v` | Runs all tests |

### The menu

```
   1. Load a sample scenario
   2. Load your own input file (.log / .facts / .txt)
   3. Type facts in by hand
   4. View current facts
   5. Run analysis and show report
   6. Why not? Explain a technique that was not detected
   7. Save last report to a text file
   8. Draw detection chain chart (matplotlib)
   9. Browse the knowledge base rules
   0. Exit
```

A normal session is 1 (pick a sample), 5 (run), then 6, 7 or 8 for follow-up
questions. Option 6 uses the explanation module: for a detected technique it shows
the chain of rules and facts, and for one that was not detected it lists which
conditions were present and which were missing.

## Input formats

The parser picks the format from the file extension. It never stops on a bad line.
It skips the line, records a warning with the line number, and the warning appears
in the report under "Input notes".

### Fact files (`.facts`, `.txt`)

One fact per line, written exactly as the rule conditions are written. Lines starting
with `#` and blank lines are ignored. A fact whose attribute is not used by any rule
is kept, with a warning, so typing mistakes are easy to spot.

```
# Run-key persistence
registry_key_modified:HKCU\Software\Microsoft\Windows\CurrentVersion\Run
new_value_points_to:executable
file_path_contains:AppData
```

### Event logs (`.log`)

One event per line: a timestamp, then `key=value` fields. Values containing spaces
go in double quotes. The field names follow Sysmon, the Windows event logging tool.

```
2026-10-14 09:12:07 EventType=ProcessCreate Image=C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe ParentImage="C:\Program Files\Microsoft Office\root\Office16\WINWORD.EXE" CommandLine="powershell.exe -NoP -W Hidden -EncodedCommand SQBFAFgA"
```

Facts are produced by four fixed extraction rules, listed in `src/input_parser.py`:

| Rule | Log field | Fact produced |
|---|---|---|
| 1 | `Image` on a ProcessCreate event | `process_created:<file name>` |
| 1 | `ParentImage` | `parent_process:<file name>` |
| 1 | `TargetImage`, `GrantedAccess`, `TargetObject` | `process_access_target`, `access_mask`, `registry_key_modified` |
| 2 | `CommandLine` | `command_line_contains:<token>` for every token that a rule looks for and that appears in the command line as a whole word, plus `command_output_redirected:true` if it contains `>` |
| 3 | any field already named like a rule attribute, e.g. `network_scan_detected=true` | passed through unchanged |
| 4 | six or more `LogonFailure` events from one `SourceIp` inside 10 minutes | `failed_login_count_exceeds:5`, `same_source_ip:true`, `time_window_minutes:10` |

Rule 2 matches whole words only, so the R002 token `/c` is not found inside
`schtasks /create`. Rule 4 is the only one that looks across several lines; it is
what turns a run of failed logins into the three facts rule R007 needs. Events that
no rule applies to (a successful logon, a network connection) are counted in the
report, not treated as errors.

## Sample inputs

| File | Scenario | Expected result |
|---|---|---|
| `01_malicious_document.log` | Word launches encoded PowerShell, which runs `systeminfo` | T1059.001, T1566.001 (chained off R001), T1082 |
| `02_brute_force.log` | Seven failed RDP logins from one IP in four minutes | T1110.001 |
| `03_persistence.facts` | Run-key autostart and a new local admin account | T1547.001, T1136.001; near miss T1543.003 |
| `04_credential_dump.log` | procdump reads LSASS, then `findstr` searches config files for passwords | T1003.001, T1552.001 |
| `05_defense_evasion.facts` | Defender switched off, plus an obfuscated script | T1562.001; near miss T1027 |
| `06_discovery_recon.log` | `tasklist /svc`, `net view /domain`, `dir /s` | T1057, T1018, T1083; near miss T1059.003 |
| `07_benign_activity.facts` | Ordinary office activity | Nothing detected, only weak near misses |
| `08_messy_input.facts` | Bad lines, duplicates, an unknown attribute | T1059.001, T1566.001 plus four warnings |

The test suite checks that every sample gives exactly these techniques.

## Report format

Every run prints the same eight-part report. It is plain ASCII so it looks the same
in PowerShell, Command Prompt and a saved text file.

| Section | Contents |
|---|---|
| 1. Summary | Number of techniques by severity, tactics in ATT&CK order, number of near misses, cycles run and why inference stopped |
| 2. Observed facts | Each fact, the input line it came from, and which rules use it |
| 3. Detected techniques | Ranked by confidence then severity, with tactic and the rule that fired |
| 4. Detection chain | Each firing in order: the IF facts (derived ones marked with their source rule) and the THEN conclusions |
| 5. Why | The explanation trace, expanded back to the observed facts |
| 6. Recommended mitigations | Merged across techniques, so a mitigation shared by two techniques appears once. M9001 is marked as team-defined |
| 7. Near misses | Rules that partly matched, their confidence (matched ÷ total conditions) and the facts still missing |
| 8. Input notes | Parser warnings, and log lines that produced no facts |

Excerpt from `01_malicious_document.log`:

```
[3] DETECTED TECHNIQUES  (ranked by confidence, then severity)
+------+-----------+------------------------------------+----------------+----------+-------+------+
| Rank | Technique | Name                               | Tactic         | Severity | Conf. | Rule |
+======+===========+====================================+================+==========+=======+======+
| 1    | T1059.001 | Command and Scripting Interpreter: | Execution      | HIGH     | 1.00  | R001 |
|      |           | PowerShell                         |                |          |       |      |
| 2    | T1566.001 | Phishing: Spearphishing Attachment | Initial Access | HIGH     | 1.00  | R018 |
| 3    | T1082     | System Information Discovery       | Discovery      | LOW      | 1.00  | R014 |
+------+-----------+------------------------------------+----------------+----------+-------+------+
```

Menu option 8 (or `--chart`) draws the same run as a diagram: observed facts on the
left, then each rule that fired, then the technique it concluded. When a technique
feeds a later rule, as T1059.001 feeds R018, the arrow runs from the technique to that
rule. Near misses are drawn dashed and grey. The border colour of a technique box
shows its severity, and the severity is also printed inside the box.

## Project structure

```
CS23533-FOAI-PROJECT/
|-- main.py                  entry point: menu, --file, --demo, --save, --chart
|-- app.py                   website (Flask), run with python app.py
|-- templates/               web pages: index.html, result.html, rules.html, base.html
|-- static/style.css         website styling (charts are saved to static/charts/)
|-- requirements.txt         flask, matplotlib
|-- data/
|   |-- rules.json           18 production rules
|   `-- mitigations.json     18 mitigations (including team-defined M9001)
|-- src/
|   |-- knowledge_base.py    Module 1: Fact, Rule, KnowledgeBase
|   |-- inference_engine.py  Modules 2 and 3: match, act, heuristic, best-first selection
|   |-- explanation.py       Module 2: WHY and WHY NOT explanations
|   |-- agent.py             Module 4: runs the full pipeline
|   |-- input_parser.py      Module 4: .facts and .log parser
|   |-- cli.py               Module 4: interactive menu
|   |-- report.py            Module 4: tabular report
|   |-- visualize.py         Module 4: detection chain chart (optional)
|   `-- test_inference.py    Module 2 and 3 walkthrough script
|-- samples/                 8 sample input files
|-- tests/
|   |-- test_act_phase.py          act phase and explanation tests
|   |-- test_input_and_report.py   parser, sample, report and menu tests
|   `-- test_web.py                website tests
|-- docs/
|   `-- DEMO_SCRIPT.md       step-by-step script for the project demo
`-- reports/                 saved reports and charts (created on first save, not committed)
```
