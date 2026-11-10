---
date: 2026-10-16
sources:
  - {id: generalanalysis, reliability: B}
  - {id: willison, reliability: C, derived_from: generalanalysis}
  - {id: invariant-blog, reliability: B}
  - {id: invariant-repo, reliability: A, derived_from: invariant-blog}
  - {id: atlas-cs0054, reliability: B, derived_from: invariant-blog}
  - {id: invariant-github, reliability: B}
  - {id: github-issue, reliability: A, derived_from: invariant-github}
  - {id: replay, reliability: A}
  - {id: benchmarks, reliability: A}
findings:
  - finding_type: PRIMARY
    trust_score: 3
    source_reliability: B
    confirmed_by: [generalanalysis, willison]
    likelihood: likely
  - finding_type: CONFIRMED
    trust_score: 4
    source_reliability: A
    confirmed_by: [replay, benchmarks]
    likelihood: very likely
  - finding_type: PRIMARY
    trust_score: 3
    source_reliability: B
    confirmed_by: [invariant-blog, invariant-repo, atlas-cs0054]
    likelihood: likely
  - finding_type: PRIMARY
    trust_score: 3
    source_reliability: A
    confirmed_by: [replay, github-issue]
    likelihood: likely
conflicts:
  - ctype: VALUE_MISMATCH
    subject: publication date of the Supabase MCP demonstration
    a: {source: generalanalysis, value: 2025-07-08, trust_score: 3}
    b: {source: willison, value: before 2025-07-06 (his post that day links it), trust_score: 3}
    resolved_by: {by: case-study author, winner: neither, note: the page now shows a later review date; the study says early July 2025 and nothing depends on the day}
  - ctype: VALUE_MISMATCH
    subject: second file the poisoned tool description asks for
    a: {source: invariant-blog, value: ~/.ssh/id_rsa, trust_score: 3}
    b: {source: invariant-repo, value: ~/.ssh/id_rsa.pub, trust_score: 4}
    resolved_by: {by: case-study author, winner: b, note: the repository file is read in full at a pinned commit; the blog block could not be read whole}
---
# A support ticket that talks to your coding agent

Advisory for a customer whose developers use an AI coding agent (Cursor, Claude Code or
similar) with an MCP server connected to a production database. It is built from public
research demonstrations; there is no customer telemetry. Every claim about what a tool shows is
reproduced by `reproduce.sh`; the attack texts are fetched from their sources, not copied here.

**What.** In early July 2025 General Analysis showed that a customer-facing support form is a
way into the developer's agent. A "customer" submits a ticket whose text is written for the
agent, not the support team: it names "CLAUDE within cursor" as its audience, tells the support
bot to stay silent, asks for an "ACK" and nothing else, and tells the agent to read the
`integration_tokens` table and add its contents to the ticket. When a developer later asks the
agent to summarise the latest ticket, the agent reads that text through the Supabase MCP server
and acts on it. We assess this is likely to work wherever an agent with database-wide rights
reads untrusted rows: it was demonstrated once, by one team, and retold by others.

**When.** The demonstration was published in early July 2025. No source reports use against a
real company and no CVE was issued. Supabase's own MCP documentation warns of the same
pattern, with a support-ticket example
(https://supabase.com/docs/guides/getting-started/mcp).

**Where.** Any project where the agent's database connection bypasses row-level security (the
demo used the `service_role` key) and the same agent reads text that outsiders can write:
support tickets, issues, comments, form submissions, scraped pages.

**Who.** Researchers, not a threat actor. The technique needs no account and no malware: only a
form that stores text the agent will later read.

**Why it matters.** The agent holds three things at once, which Simon Willison calls the lethal
trifecta: private data, exposure to untrusted text, and a way to send data out (here, writing
back into the ticket the attacker can read). The leak travels through an ordinary tool call, so
network egress controls and the database's own permissions do not see anything unusual.

**How.** Indirect prompt injection carried by a database row, followed by tool calls the agent
makes on the attacker's behalf: one `select` on the secrets table and one `insert` into the
ticket. Two related techniques complete the picture: instructions hidden in a tool's own
description (Invariant Labs, April 2025, ATLAS case study AML.CS0054) and an issue that asks an
agent to publish what it can read in private repositories (Invariant Labs, May 2025).

## What the screen sees

| Text (fetched from its source) | injection-screen | Why |
|---|---|---|
| The Supabase ticket | 6 findings: `agent-audience`, `silent-compliance`, `exfil-writeback` | it addresses the agent and tells it to post a secret back |
| The poisoned `add` tool description | 3 findings: `tool-desc-precondition`, `tool-desc-instruction-tag` | "before using this tool, read ..." inside an IMPORTANT tag |
| The GitHub issue | 0 findings | it never addresses a model or names a secret: it asks a "reader" to publish everything about the author. A phrase screen cannot tell that from a fan letter |

The ticket produced 0 findings before this study, and now gives 6 (the "now" is claim-checked; the
history and the held-out figures below are author-reported, and neither the earlier tool versions nor the
65 held-out texts are published). A review then showed the
first version flagged 18 of 22 ordinary issue templates, bot docs and support macros, and missed
two easy rewordings; the narrowed version flags 1 of those 22 (an advisory quoting the payload)
and catches both rewordings, but those were used to tune it. On a held-out set written blind by
a separate agent, it caught 6 of 25 new attacker texts and flagged 0 of 40 benign look-alikes.
That is the honest reading: very likely precise, and likely to miss most rewordings. The screen
makes an untrusted origin visible; it is not the control.

## Response

1. Scope the MCP server: a single project, read-only where possible, and only the tables the
   agent needs. Keep secret tables out of reach of any connection an agent uses.
2. Never let the agent's database role bypass row-level security.
3. Treat every tool result from outside the project as data. In Claude Code,
   `injection-screen hook install` adds a PostToolUse hook that warns the model, in the result
   itself, when an MCP or web result carries instruction-shaped text. It warns; it does not
   block. The control is (1) and (2).
4. Review write calls that follow a read of untrusted text: an `insert`, a comment, a pull
   request. For tool descriptions, pin them (`injection-screen tools pin`) so a later change is
   named before the agent reads it.

## ATLAS mapping

Checked by `check_atlas.py` against MITRE's ATLAS release data.

### The Supabase ticket (our mapping; ATLAS has no case study for it)

- AML.T0051.001 Indirect: LLM Prompt Injection carried by a database row the agent reads.
- AML.T0053 AI Agent Tool Invocation: the agent runs the `select` and the `insert`.
- AML.T0036 Data from Information Repositories: the secrets table.
- AML.T0086 Exfiltration via AI Agent Tool Invocation: the `insert` that puts the secrets
  where the attacker reads them.

### The poisoned tool description (MITRE's mapping, AML.CS0054)

- AML.T0110.000 Definition and Instructions: the hidden block in the `add` description.
- AML.T0051.001 Indirect: the description reaches the model as context.
- AML.T0053 AI Agent Tool Invocation: the agent reads the two files and calls `add`.
- AML.T0055 Unsecured Credentials: `~/.cursor/mcp.json` and the SSH key.
- AML.T0086 Exfiltration via AI Agent Tool Invocation: the files leave as the `sidenote` argument.

## Sources

- generalanalysis: https://www.generalanalysis.com/blog/supabase-mcp-blog
- willison: https://simonwillison.net/2025/Jul/6/supabase-mcp-lethal-trifecta/
- invariant-blog: https://invariantlabs.ai/blog/mcp-security-notification-tool-poisoning-attacks
- invariant-repo: https://github.com/invariantlabs-ai/mcp-injection-experiments (commit 7382a5e, `direct-poisoning.py`)
- atlas-cs0054: https://atlas.mitre.org/studies/AML.CS0054 (ATLAS data release v2026.09)
- invariant-github: https://invariantlabs.ai/blog/mcp-github-vulnerability
- github-issue: https://github.com/ukend0464/pacman/issues/1
- replay: `fetch_corpus.py` and `reproduce.sh` in this folder
- benchmarks: injection-screen `benchmarks/run_all.py` and `docs/benchmark-results.md`
