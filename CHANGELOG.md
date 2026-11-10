# Changelog

## 0.1.1 (2026-11-09)

- The tools are pinned at their 0.1.1 releases. instinct-delivery's agent-security pack grew from
  nine rules (91 cases) to twelve (151); the replayed attack flows warn exactly as before.
- Where it falls short, with a limits page; the tools pinned at their current release commits.
- MITRE ATT&CK 20.0 is fetched from a fixed commit, so its pinned hash cannot move under it.
- Study 2 is described as research demonstrations, not an attack; the held-out figures and each
  study's before-and-after history are marked author-reported.

## 0.1.0 - 2026-10-19

Two studies, each with a script that reproduces its claims.

- `mini-shai-hulud`: an npm worm that plants a Claude Code hook and a VS Code folder-open task.
  13 claims, run against inert replay files.
- `mcp-prompt-injection`: a support ticket, a poisoned tool description and a GitHub issue that
  target an agent. 13 claims; the attack texts are fetched from their authors and checked
  against recorded SHA-256 hashes.
- Each `reproduce.sh` exits 0 (every claim reproduced), 1 (a claim failed) or 2 (none failed,
  but some could not run: a tool or an input was missing). Exit 2 is never a pass.
- `check_attack.py` and `check_atlas.py` check each technique mapping against MITRE's own data.
