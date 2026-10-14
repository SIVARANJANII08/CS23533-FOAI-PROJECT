# Demo script

About 8 minutes. Run everything from the project folder in the VS Code terminal.
Command Prompt is easier to read than PowerShell for the wide tables, so switch the
terminal to Command Prompt and maximise it before starting.

## Before the demo

```
cd CS23533-FOAI-PROJECT
python -m unittest discover tests
pip show matplotlib
```

All tests should pass (31 at the time of writing). If matplotlib is missing, install it
with `pip install matplotlib` or skip step 5. Delete the `reports/` folder so the saved
files you show are fresh.

## 1. Start the program (30 seconds)

Type `python main.py`.

Say: "This is a rule-based expert system. It loads 18 IF-THEN rules covering 6 ATT&CK
tactics and 18 mitigations from the JSON knowledge base, then waits for input."

Point at the line `Loaded 18 rules across 6 tactics and 18 mitigations.`

## 2. Show the rules (1 minute)

Choose `9`, then type `R001`.

Say: "Each rule is a production rule. R001 fires only when all three facts are
present: PowerShell was started, its command line contains -EncodedCommand, and its
parent was Word. When it fires it asserts two new facts, technique_detected and
tactic_detected, into working memory."

Then choose `9` again and type `R018`. Say: "R018 has technique_detected:T1059.001 as one
of its conditions. It cannot fire from raw input. It can only fire after R001 has, which
is how rules chain."

## 3. Run the main scenario (2 minutes)

Choose `1`, then `1` (`01_malicious_document.log`). Choose `5`.

Walk down the report:

- Input line: "The parser read four log events and pulled out eight facts."
- Section 2: "Each fact shows the log line it came from and which rules use it.
  Three facts, like parent_process:explorer.exe, are not used by any rule."
- Section 4: "Three cycles. R001 fired in cycle 1. In cycle 2 R018 fired, and its
  first condition is marked 'from R001', so it used a conclusion, not an observation.
  R014 fired in cycle 3."
- Section 3: "All three have confidence 1.00 because every condition matched. Ties are
  broken by severity, so the two HIGH techniques come before the LOW one."
- Section 5: "The explanation expands T1566.001 back to the three observed facts that
  started the chain."
- Section 6: "Mitigations are merged. M9001 is flagged as team-defined."

## 4. Ask "why not?" (1 minute)

Choose `1`, then `5` (`05_defense_evasion.facts`). Choose `5` to run it.

Point at section 7: T1027 is a near miss at 0.67, with 2 of 3 conditions met.

Choose `6` and type `T1027`. Say: "The system can explain a conclusion it did not reach.
FromBase64String and high entropy were both present, but script_length_exceeds:1000
was missing, so R011 never fired."

## 5. Draw the chain (1 minute)

Choose `1`, `1`, `5` to go back to the malicious document, then choose `8` and answer
`y` to open the window.

Say: "Observed facts are on the left. Arrows show which facts each rule needed. The
arrow from the T1059.001 box into R018 is the chained step." Close the window to
return to the menu.

## 6. Brute force from raw logs (1 minute)

Choose `1`, then `2` (`02_brute_force.log`). Choose `4` to view the facts.

Say: "The log has ten lines and none of them says 'brute force'. The parser counted
seven LogonFailure events from 203.0.113.45 inside four minutes. That is more than five
inside a ten-minute window, so it asserted the three facts R007 needs. The two
failures from 10.0.0.12 stayed below the threshold."

Choose `5` and point at T1110.001 in section 3.

## 7. Bad input and a clean result (1 minute)

Choose `1`, then `8` (`08_messy_input.facts`), then `5`. Scroll to section 8.
Say: "Malformed lines are skipped with their line numbers, and the run still
completes."

Choose `1`, then `7` (`07_benign_activity.facts`), then `5`. Say: "Normal activity gives
no detections. A few rules partly match, but at 0.33 or 0.50 they stay as near misses.
A rule only fires when every condition is met."

## 8. Save and exit (30 seconds)

Choose `7` and press Enter to accept the default name. Choose `0`.

If asked, show the non-interactive form:

```
python main.py --file samples/04_credential_dump.log --save reports/cred.txt --chart reports/cred.png
```

## Questions to expect

**Is this a website?**
No. It is a Python command-line program. Input comes from files or the keyboard, and
output is a text report plus an optional PNG chart.

**Where does the log data come from?**
The sample logs are written by the team in a simplified Sysmon format. They are not
captured from a live machine. The point is to show how raw events become facts.

**How does the parser decide what to extract?**
Four fixed extraction rules, listed in the README. For command lines it only looks for
tokens that some rule already uses, and only as whole words, so `/c` does not match
inside `/create`. It adds nothing the rules could not use.

**Why "more than five" failed logins?**
R007's condition is `failed_login_count_exceeds:5`, so the parser needs at least six.
The tests check that five failures do not trigger it and six do.

**What does confidence mean?**
Matched conditions divided by total conditions, the Module 3 heuristic. A detected
technique is always 1.00. Below 1.00 it is a near miss and the rule did not fire.

**Why does the benign file show near misses?**
`process_created:cmd.exe` is one of R002's three conditions. One out of three gives
0.33. It is reported so an analyst can see what else to look for, but nothing is
concluded.

**What happens with a typo in a fact?**
The fact is kept, and the report warns that no rule uses that attribute. See
`user_mood:suspicious` in sample 08.

**What is M9001?**
A team-defined code, not an official ATT&CK mitigation. ATT&CK gives no preventive
mitigations for Discovery techniques, so M9001 holds detection guidance instead. The
report marks it with an asterisk.
