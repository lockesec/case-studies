# Overstated draft (lint fixture)

<!-- Written for this case study as the kind of draft a tired analyst sends at 03:00: the same
facts as ../report.md, stated harder than the evidence allows. reproduce.sh shows
cti-report-lint blocking it. -->

The 2026-05-19 npm compromise was certainly the work of TeamPCP, the same group behind the
2025 Shai-Hulud worm. Over 300 packages were affected, with no doubt about the count. The worm writes a SessionStart hook into
.claude/settings.json and a folder-open task into .vscode/tasks.json.

It is impossible for these hooks to survive a lockfile rollback once the package is removed.
We are 95% confident no customer repository was modified.
