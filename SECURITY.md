# Security policy

## What this repository contains

Write-ups of public attacks, and scripts that replay them. Every replayed file is inert: it
only prints a line or holds harmless text, and the scripts write only into a temporary
directory that is removed on exit. Indicators in the reports are defanged. The second study
fetches published attack texts to check them against recorded hashes; nothing fetched is
executed.

## Reporting

Report a vulnerability, or a replay file that is not inert, **privately** with GitHub's
"Report a vulnerability" button on this repository (Security, then Advisories). Please do not
open a public issue for it. Factual errors in a report are ordinary issues.

Only the main branch receives fixes.
