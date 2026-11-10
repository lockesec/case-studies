# case-studies

**Two attacks on AI coding agents, written up and re-run with one script: a live npm supply-chain
compromise, and a set of published prompt-injection research demonstrations.**

Each study takes one publicly reported attack (or attack technique) and writes it up the way a security team briefs
a customer after an incident. It then replays what the attack leaves on disk, using harmless
stand-in files, and runs the tools a defender would reach for. The findings are stated as
numbered claims, and each study's `reproduce.sh` checks every one. You can watch each claim
hold, or fail.

```console
$ sh mini-shai-hulud/reproduce.sh
...
13 reproduced, 0 failed, 0 skipped (of 13 claims)
$ sh mcp-prompt-injection/reproduce.sh
...
13 reproduced, 0 failed, 0 skipped (of 13 claims)
```

The scripts check how the tools behave at the pinned commits. Where a study says how a tool
behaved before it ("the first run listed the hook with no mark"), that is author-reported
history: each tool is published as a single release commit, so no earlier version exists to check.

Designed for:

- **Reading.** You need nothing. Open a study's README; it starts with what was found.
- **Checking a claim.** You need the tool that claim names. A claim whose tool is missing is skipped,
  not passed. All five are under [Reproduce](#reproduce).
- **Checking every claim.** You also need MITRE's data files, a checkout of instinct-delivery, and the
  network for the second study. Setup is under [Reproduce](#reproduce).

## Studies

| Study | Attack | What it shows |
|---|---|---|
| [mini-shai-hulud](mini-shai-hulud/) | npm worm, 2026-05-19, ATT&CK [S9043](https://attack.mitre.org/software/S9043/): plants a Claude Code `SessionStart` hook and a VS Code folder-open task that outlive the package | config that RUNS code: what a checkout runs on its own, drift after a baseline, why a prompt-injection screen correctly sees nothing; 13 claims |
| [mcp-prompt-injection](mcp-prompt-injection/) | a support ticket that tells the developer's agent to post a secrets table back into the ticket (General Analysis, 2025-07), with a poisoned MCP tool description (ATLAS [AML.CS0054](https://atlas.mitre.org/studies/AML.CS0054)) and a hijacking GitHub issue | text that PERSUADES the agent: what a screen catches at the moment a tool result arrives, which of the agent's next calls get a warning, what neither catches and why, tool-description pinning; 13 claims |

The two are deliberately opposite: one attack never speaks to the model, the other only speaks
to it. Each tool is right in one and silent in the other, and the studies show both.

## The tools

Five small open tools, each a separate project that works alone. Here they are used together,
each for the question it is built to answer, so you can see where one stops and the next starts.

- [hook-integrity-kit](https://github.com/lockesec/hook-integrity-kit): what a checkout runs on its own.
- [injection-screen](https://github.com/lockesec/injection-screen): text written to steer the model.
- [instinct-delivery](https://github.com/lockesec/instinct-delivery): warnings delivered to the agent as it acts.
- [cti-report-lint](https://github.com/lockesec/cti-report-lint): does a report claim only what its sources support.
- [publish-gate](https://github.com/lockesec/publish-gate): is a repository safe to make public.

## Which tool did what

| Question | Tool | Mini Shai-Hulud | MCP prompt injection |
|---|---|---|---|
| What will this checkout run on its own? | hook-integrity-kit `audit` | lists the planted hook and the folder-open task, even after the package is removed | not applicable |
| Has the hook surface changed since I reviewed it? | hook-integrity-kit `bless` / `verify` | DRIFT: dropper added, hooks block changed | not applicable |
| Is there text written to steer the model? | injection-screen | 0 findings: correct, the worm never talks to the model | ticket 6 findings, tool description 3, GitHub issue 0 (a stated gap) |
| Did a tool's description change after approval? | injection-screen `tools pin` / `check` | not applicable | `CHANGED add` on a rug pull |
| Is the agent told, at the moment it acts? | instinct-delivery | not applicable: the writer is npm, not the agent | 6 of 22 calls warned, all in attack sessions, 0 in benign twins; the GitHub flow and the poisoned call are not caught (stated) |
| Does the write-up claim only what its sources support? | cti-report-lint | passes; circular sources counted once | passes; one demonstration retold many times stays one source |
| Is the mapping MITRE's, or ours? | `check_attack.py`, `check_atlas.py` | 8 techniques and the group in ATT&CK's S9043 record | 9 mapping lines, 6 distinct ids, in ATLAS v2026.09 |
| Is this repository safe to make public? | publish-gate | clean | clean |

Each study states what its tools miss, and `reproduce.sh` asserts the miss: if a tool later
closes the gap, the claim fails and the doc must change.

## Reproduce

Install the five tools, then run each study. `ID` is the path to your checkout of
instinct-delivery; the second study reads that tool's example rule pack from it.

    pip install git+https://github.com/lockesec/hook-integrity-kit \
                git+https://github.com/lockesec/injection-screen \
                git+https://github.com/lockesec/cti-report-lint \
                git+https://github.com/lockesec/publish-gate \
                git+https://github.com/lockesec/instinct-delivery
    git clone https://github.com/lockesec/instinct-delivery && export ID=$PWD/instinct-delivery
    curl -LO https://raw.githubusercontent.com/mitre-attack/attack-stix-data/20664a889568dce884a1dac0ec7b12ae3a199f51/enterprise-attack/enterprise-attack-20.0.json
    ATTACK_JSON=enterprise-attack-20.0.json sh mini-shai-hulud/reproduce.sh
    curl -LO https://github.com/mitre-atlas/atlas-data/releases/download/v2026.09/ATLAS-2026.09.yaml
    ATLAS_YAML=ATLAS-2026.09.yaml sh mcp-prompt-injection/reproduce.sh     # fetches the attack texts

- **Inputs.** The first study needs MITRE's ATT&CK data file. The second needs the ATLAS file
  and the network: it fetches the published attack texts from their authors' pages.
- **Exit codes.** 0: every claim reproduced. 1: a claim failed. 2: none failed, but some could
  not run.
- **A SKIP is not a pass.** A claim SKIPs, with the cause printed, when its tool is not
  installed or its input (the MITRE file, a fetched text) is missing or unreadable.
- **Safe to run.** Replays write only inert files into a temporary directory. Fetched texts are
  checked against a recorded SHA-256 and never executed. No malware or live indicator is involved.
- **CI pins the inputs.** [`reproduce.yml`](.github/workflows/reproduce.yml) runs both studies
  on every push and weekly, with each tool pinned to a release commit and the MITRE files
  (ATT&CK 20.0, ATLAS 2026.09) checked by SHA-256. It fails unless both print
  `13 reproduced, 0 failed, 0 skipped`. The commands above take the latest tools and ATT&CK file.

## Where it falls short

- **Two attacks are not a benchmark.** These show how the tools behave on these two cases, not how often they catch attacks. Each tool's catch rate, where measured, is in its own repository.
- **The replays are stand-ins.** Harmless files reproduce what each attack leaves on disk, not the live attack.
- **The tools' author wrote the studies,** and gaps found while writing them were fixed in the tools first. No outside party has checked them.
- **The second study needs the network.** It fetches attack texts from their authors' pages, and a page that changes shows up as a skipped claim.

How it was checked and what is untested: [docs/limits.md](docs/limits.md).

## Ground rules for every study

- **Sources are named and graded.** Each fact in a report cites a declared source with a
  reliability grade; a source that repeats another is marked as derived from it, so a story
  retold by three outlets counts once.
- **Disagreements stay visible.** Where vendors disagree (file names, package counts), both
  versions are recorded and the replay covers both.
- **Indicators are defanged** and quoted as text; nothing in this repository resolves or
  fetches them.
- **Third-party text is fetched, not copied.** Attack texts stay with their authors; a study
  pins their hashes instead.
- **A tool's gap is a finding.** Writing these studies exposed gaps in the tools themselves: a
  `SessionStart` hook listed without a mark, and a published injection ticket passing the screen
  with 0 findings. Each was fixed in its tool, with tests, before the claim was written here.

## Credits · License

Facts come from the vendor and MITRE pages listed in each report's Sources section; ATT&CK is a
trademark of The MITRE Corporation and is used for identification.

The maintainer designed and directed this work. Much of the code and text was written with AI coding agents, and separate AI sessions reviewed it adversarially; the claims `reproduce.sh` checks show what was verified.

Apache-2.0 - see [LICENSE](LICENSE) and [NOTICE](NOTICE).
