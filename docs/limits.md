# Limits

## How well it works

There is no catch rate here. A claim is one statement about one tool on one case, and `reproduce.sh` checks it.

- **26 claims, 13 in each study.** Each script exits 0 when every claim reproduced, 1 when one failed, and 2 when none failed but some could not run.
- **Misses are claims too.** Where a tool is meant to miss something, the script asserts the miss, so a tool that closes the gap fails the claim and the document has to change.
- **The workflow pins each tool to a release commit,** and MITRE's data files to a hash. A change reaches it only through a pull request that bumps a pin.

## Not tested

- Any attack beyond these two.
- The live attacks. Only what they leave on disk is replayed, with inert files.
- Review by anyone outside this project.

## Out of scope on purpose

- Copying third-party attack text here. It is fetched from its authors and pinned by hash, so a claim that needs it is skipped when it is unavailable.
- Resolving or fetching indicators. They are defanged and quoted as text.

## Known holes

- **Fixed before written.** Gaps these studies exposed were fixed in the tools first, so the results describe the tools after that work, and the studies were not held out.
- **Fetched pages can move.** A changed or missing attack text shows as a skip, not a pass.
- **Unpinned commands in the README.** Its Reproduce section installs the latest tools and fetches the current ATT&CK file, so numbers there can differ from the pinned workflow.
