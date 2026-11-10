# Contributing

- Run both `reproduce.sh` scripts (see the README for the install and the MITRE files). Each
  must end `13 reproduced, 0 failed, 0 skipped`, or you must say which claims skipped and why.
- A claim in a report or README that a tool shows something needs a check in that study's
  `reproduce.sh`. A change that alters a claim changes its check in the same commit.
- Keep replay files inert, and keep indicators defanged. Do not copy third-party attack text
  into the repository: fetch it and pin its SHA-256, as `fetch_corpus.py` does.
- Each example directory carries a `SYNTHETIC-DATA` file stating that its contents were
  invented; keep it, and add one to any new example directory.
- Run `publish-gate` on the repository before you open a pull request.
