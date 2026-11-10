---
date: 2026-10-16
sources:
  - {id: socket, reliability: B}
  - {id: safedep, reliability: B}
  - {id: aikido, reliability: B}
  - {id: stepsecurity, reliability: B}
  - {id: sonar, reliability: B}
  - {id: securonix, reliability: B}
  - {id: upwind, reliability: B}
  - {id: flashpoint, reliability: B}
  - {id: chainguard, reliability: C}
  - {id: thn, reliability: C, derived_from: socket}
  - {id: lilting, reliability: C, derived_from: safedep}
  - {id: mitre-s9043, reliability: B, derived_from: flashpoint}
  - {id: replay, reliability: A}
findings:
  - finding_type: CONFIRMED
    trust_score: 4
    source_reliability: B
    confirmed_by: [safedep, sonar, lilting]
    likelihood: very likely
  - finding_type: CONFIRMED
    trust_score: 4
    source_reliability: B
    confirmed_by: [socket, safedep, aikido, stepsecurity, thn]
    likelihood: very likely
  - finding_type: DERIVED
    trust_score: 3
    source_reliability: B
    confirmed_by: [mitre-s9043, flashpoint]
    likelihood: likely
  - finding_type: CONFIRMED
    trust_score: 5
    source_reliability: A
    confirmed_by: [replay, safedep]
    likelihood: almost certain
conflicts:
  - ctype: VALUE_MISMATCH
    subject: number of packages and versions in the 2026-05-19 wave
    a: {source: socket, value: 323 packages / 639 versions, trust_score: 4}
    b: {source: safedep, value: 317 packages / 637 versions, trust_score: 4}
    resolved_by: {by: case-study author, winner: neither, note: reported as a range of 317 to 323 packages; neither count changes the response}
---
# Mini Shai-Hulud: an npm worm that persists through AI coding agents

Case study written as an MDR advisory to a customer running Node.js projects with Claude Code
and VS Code. It is built only from public reporting; there is no customer telemetry. Every
claim about what a tool shows is reproduced by `reproduce.sh` in this folder.

**What.** On 2026-05-19 a compromised npm maintainer account (`atool`, which publishes the
`@antv` scope, `echarts-for-react`, `timeago.js` and others) published between 317 and 323
packages with a credential-stealing worm. Besides stealing tokens and republishing itself, the
worm writes four files into every Node.js project it can reach: a `SessionStart` hook in
`.claude/settings.json`, a VS Code task in `.vscode/tasks.json` that runs when the folder
opens, a dropper script (`setup.mjs`) beside each, and a CI workflow named "Run Copilot" in
`.github/workflows/codeql.yml` that dumps the repository's secrets. That the worm
writes these four files is very likely: SafeDep and Sonar describe them independently for this
wave (lilting.ch retells SafeDep), and SafeDep publishes the decrypted `.claude/settings.json`
block. Securonix and Upwind describe the same files in samples
from the weeks before 19 May, in which the hook runs `.vscode/setup.mjs` and the payload is
`router_runtime.js`; the replay covers both forms.

**When.** All times 2026-05-19 UTC. The first orphan commit was pushed to `antvis/G2` at
01:25; publishing began at 01:39 by SafeDep's timeline and at about 01:56 by Socket's; Socket's
first detection followed at about 02:02 and its write-up the same morning. No source gives the
time npm removed the packages.

**Where.** Developer workstations and CI runners that installed an affected version, and every
local Node.js project on such a workstation, because the worm copies its hooks into them. The
artefacts are committed project files, so they travel with `git push`.

**Who.** MITRE ATT&CK lists the worm as S9043, derived from the 2025 Shai-Hulud worm (S9008),
and lists TeamPCP (G1056) as the group using it. Attribution of this wave to TeamPCP is likely
(Flashpoint names the AntV wave as TeamPCP's, and MITRE lists the group as using the worm, but
the group released the worm's source code, so a copycat
cannot be excluded). No source attributes the 2025 worm to the same group.

**Why it matters.** The hooks outlive the package. Rolling back the lockfile or removing the
package does not remove them: the next time an agent session starts or the folder opens, the
dropper runs again. This is almost certain: it follows from how both editors run these files,
the replay in this folder shows the files untouched after the package is gone, and SafeDep
documents the hooks coming back after the packages are removed (Flashpoint repeats SafeDep).

**How.** Install time: a `preinstall` script runs a 486-498 KB obfuscated `index.js` with the
Bun runtime, and an optional git dependency pointing at an orphan `antvis/G2` commit gives a
second route through the dependency's `prepare` script. The payload harvests GitHub, npm, cloud
and CI credentials, exfiltrates them over HTTPS and to public GitHub repositories with
Dune-themed names, republishes every package the stolen npm tokens can publish, and installs
host persistence (a `kitty-monitor` user service polling GitHub for signed commands).

## Detection

| Signal | Where | What catches it |
|---|---|---|
| A `SessionStart` hook you did not add, matcher `*`, running `node .claude/setup.mjs` or `node .vscode/setup.mjs` | `.claude/settings.json` | `hook-integrity-kit audit` lists it with a review note; `verify` reports DRIFT after a bless |
| A task labelled "Environment Setup" with `runOn: folderOpen` | `.vscode/tasks.json` | `hook-integrity-kit audit` flags it |
| A new `setup.mjs` reached from a hook | `.claude/`, `.vscode/` | `hook-integrity-kit verify`: ADDED |
| A workflow named "Run Copilot" on branch `chore/add-codeql-static-analysis`, commit message `fix: ci` | `.github/workflows/codeql.yml` | not covered by these tools; review CI changes |
| A write to `.claude/settings.json` by `node`, `bun`, `sh` or `bash` (not by Claude Code itself); a write to `.vscode/tasks.json` by those whose parent runs from `/tmp` or `node_modules` | endpoint telemetry | Securonix's published analytic (Sysmon for Linux, event 11); hook-integrity-kit ships a Sigma rule in the same spirit |

## Response

Order matters: Flashpoint and lilting both report a token whose revocation wipes the home
directory while the persistence is live.

1. Isolate the host from the network.
2. Remove the persistence: the `.claude/` and `.vscode/` artefacts above in every project, the
   `kitty-monitor` and `gh-token-monitor` user services or launch agents, and
   `/var/tmp/.gh_update_state`.
3. Roll back the lockfile and clear package caches, proxies and image layers.
4. Check every repository for the "Run Copilot" workflow and the branch above.
5. Rotate GitHub, npm, cloud and CI credentials; then revoke the old ones.
6. Look for public repositories in the account whose description is the reversed string
   `niagA oG eW ereH :duluH-iahS`.

## ATT&CK mapping

Checked by `check_attack.py` against MITRE's own bundle (ATT&CK v20.0): every technique below
is one S9043 is recorded as using.

- T1195.001 Compromise Software Dependencies and Development Tools: the poisoned packages.
- T1546 Event Triggered Execution: the `SessionStart` hook and the folder-open task.
- T1554 Compromise Host Software Binary: MITRE's mapping for the agent config files that act as
  execution triggers (a loose fit for a configuration file, but it is MITRE's).
- T1059.007 Command and Scripting Interpreter: JavaScript: the dropper and payload.
- T1677 Poisoned Pipeline Execution: the injected workflow job.
- T1543.002 Create or Modify System Process: Systemd Service: `kitty-monitor`.
- T1567.001 Exfiltration to Code Repository: the Dune-named repositories.
- T1485 Data Destruction: the wipe on token revocation.

MITRE ATLAS AML.T0081 "Modify AI Agent Configuration" (in the ATLAS data release v2026.09) is
adjacent: it covers changing what an agent is told or allowed, while this worm uses the hook
surface to run code.

## Indicators (defanged)

- C2: `t[.]m-kosche[.]com`, path `/api/public/otel/v1/traces`
- Optional dependency `@antv/setup` -> `github:antvis/G2#1916faa365f2788b6e193514872d51a242876569`
- Payload `index.js` SHA-256 `a68dd1e6a6e35ec3771e1f94fe796f55dfe65a2b94560516ff4ac189390dfa1c` (SafeDep)
- Exfiltration repositories named `<dune-word>-<dune-word>-<digits>`
- Payload names `.claude/index.js` (this wave, SafeDep); `.claude/router_runtime.js` (the earlier
  samples, Securonix and Upwind)

## Sources

- socket: https://socket.dev/blog/antv-packages-compromised
- safedep: https://safedep.io/mini-shai-hulud-strikes-again-314-npm-packages-compromised/
- aikido: https://www.aikido.dev/blog/mini-shai-hulud-antv-npm-supply-chain-attack
- stepsecurity: https://www.stepsecurity.io/blog/shai-hulud-here-we-go-again-mass-npm-supply-chain-attack-hits-the-antv-ecosystem
- sonar: https://www.sonarsource.com/blog/mini-shai-hulud-targets-ai-coding-agents/
- securonix: https://connect.securonix.com/threat-research-intelligence-62/beta-detection-mini-shai-hulud-claude-code-or-vs-code-persistence-hook-injection-analytic-311
- upwind: https://www.upwind.io/feed/mini-shai-hulud-npm-supply-chain-worm
- flashpoint: https://flashpoint.io/blog/mini-shai-hulud-worm-new-era-ci-cd-exploitation/
- chainguard: https://chainguard.dev/unchained/mini-shai-hulud-npm-attack-antv-ecosystem-compromise-may-2026
- thn: https://thehackernews.com/2026/05/mini-shai-hulud-pushes-malicious-antv.html
- lilting: https://lilting.ch/en/articles/mini-shai-hulud-antv-npm-claude-code-vscode-persistence
- mitre-s9043: https://attack.mitre.org/software/S9043/
- replay: `replay/build_fixture.py` and `reproduce.sh` in this folder
