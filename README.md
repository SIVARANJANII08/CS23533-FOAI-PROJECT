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
| Sivaranjanii M | 241901109 | `data/`: knowledge base, rules, mitigations; act phase and explanation trace (Module 2) |

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
| 4. Agent integration, interface and testing | Goal-based intelligent agent |

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

## Project structure
