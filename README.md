# MITRE ATT&CK Rule-Based Navigator

A classical AI expert system that maps observed system behaviours to MITRE ATT&CK
techniques and recommends mitigations, with a fully explainable reasoning chain.

AI Foundations Mini-Project
Supervisor: Dr. S. Bhuvana

## Team

| Member | Roll No | Owns |
|---|---|---|
| Pranathee H | 241901078 | `src/` — inference engine, search, agent |
| Sivaranjanii M | 241901109 | `data/` — knowledge base, rules, mitigations |

## Approach

The system uses classical (symbolic) AI only. No machine learning is involved.
This is a deliberate design decision: in a security context an analyst must be able
to see *why* a technique was flagged, and a rule chain provides that audit trail
while a statistical model does not.

| Module | AI technique |
|---|---|
| 1. Knowledge Base and Fact Representation | Knowledge representation via IF-THEN production rules |
| 2. Forward Chaining Inference Engine | Forward chaining |
| 3. Best-First Search and Heuristic Prioritisation | Best-first search, heuristic = matched ÷ total conditions |
| 4. Agent Integration, Interface, and Testing | Goal-based intelligent agent |

## Project structure