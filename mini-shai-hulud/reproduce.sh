#!/bin/sh
# Reproduce every claim this case study makes about what a tool shows.
#
#   sh reproduce.sh                      # tools on PATH, no ATT&CK file: the mapping claims SKIP
#   ATTACK_JSON=enterprise-attack.json sh reproduce.sh
#
# Tools (each is optional; a missing one makes its claims SKIP, never PASS):
#   hook-integrity-kit, injection-screen, cti-report-lint, publish-gate
# ATTACK_JSON: MITRE's enterprise-attack.json from the attack-stix-data repository (v20.0 or
#   later; MITRE created the S9043 record on 2026-07-29). Nothing is bundled.
# PUBLISH_GATE_DENYLIST: your private names, for the publish-gate claim; without it the gate
#   runs with --no-denylist and says so.
#
# Every replayed file is inert (see replay/build_fixture.py) and lives in a temporary directory
# that is removed on exit. Exit 0: every claim reproduced. 1: a claim failed. 2: none failed
# but some were skipped, so not everything was shown.
set -u
HERE=$(cd "$(dirname "$0")" && pwd)
PY=${PYTHON:-python3}
WORK=$(mktemp -d "${TMPDIR:-/tmp}/mini-shai-hulud.XXXXXX")
trap 'rm -rf "$WORK"' EXIT INT TERM
mkdir "$WORK/empty-claude-home"          # so a verify never reads the runner's own ~/.claude
pass=0 fail=0 skip=0

have() { command -v "$1" >/dev/null 2>&1; }

result() {
    case $1 in PASS) pass=$((pass + 1)) ;; FAIL) fail=$((fail + 1)) ;; SKIP) skip=$((skip + 1)) ;; esac
    printf '%-4s  %-3s %s\n' "$1" "$2" "$3"
}

# check ID TEXT WANT_EXIT GOT_EXIT OUTFILE [PATTERN...]; a PATTERN starting with NOT: must be absent
check() {
    id=$1 text=$2 want=$3 got=$4 out=$5
    shift 5
    if [ "$got" != "$want" ]; then
        result FAIL "$id" "$text (exit $got, expected $want)"; sed 's/^/        /' "$out"; return
    fi
    for pat in "$@"; do
        case $pat in
            NOT:*) if grep -qF -- "${pat#NOT:}" "$out"; then
                    result FAIL "$id" "$text (should not contain: ${pat#NOT:})"; sed 's/^/        /' "$out"; return
                fi ;;
            *) if ! grep -qF -- "$pat" "$out"; then
                   result FAIL "$id" "$text (missing: $pat)"; sed 's/^/        /' "$out"; return
               fi ;;
        esac
    done
    result PASS "$id" "$text"
}

# check_ne ID TEXT WANT GOT OUTFILE [PATTERN...]: like check, but for a tool whose exit 2 means
# NOT EVALUABLE (an input missing or unreadable, a dependency absent): that scores SKIP with the
# tool's own printed cause, never FAIL, because nothing was shown either way.
check_ne() {
    if [ "$4" = 2 ] && [ "$3" != 2 ]; then
        result SKIP "$1" "$2 (NOT EVALUABLE, exit 2: $(head -n 1 "$5"))"
        return
    fi
    check "$@"
}

build() { "$PY" "$HERE/replay/build_fixture.py" "$@"; }

echo "== hook-integrity-kit: what the checkout runs on its own, and drift after a bless"
if have hook-integrity-kit; then
    build "$WORK/clean" --stage clean
    hook-integrity-kit audit --root "$WORK/clean" >"$WORK/o" 2>&1
    check H1 "a clean project: its one hook is listed, nothing flagged" 0 $? "$WORK/o" \
        "1 item(s) run on their own, 0 flagged"

    build "$WORK/inf" --variant claude
    hook-integrity-kit audit --root "$WORK/inf" >"$WORK/o" 2>&1
    h2=$?
    cp "$WORK/o" "$WORK/h2"
    check H2 "infected (hook runs .claude/setup.mjs): hook listed and noted, folder-open task flagged" 1 $h2 "$WORK/o" \
        "SessionStart (.claude/settings.json): node .claude/setup.mjs" \
        "? runs when a session starts, before the first prompt" \
        "VS Code task 'Environment Setup' (.vscode/tasks.json): node .claude/setup.mjs" \
        "! runs when the folder opens (runOn: folderOpen)"
    # the gap claim reads the SAME run as H2 and needs proof that audit ran and listed things:
    # a crashed or absent audit also lacks codeql.yml, and must not pass as a known gap
    check H3 "known gap: the injected CI workflow job is not audited (update the docs if this fails)" 1 $h2 "$WORK/h2" \
        "item(s) run on their own" "VS Code task 'Environment Setup'" "NOT:codeql.yml"

    build "$WORK/infv" --variant vscode
    hook-integrity-kit audit --root "$WORK/infv" >"$WORK/o" 2>&1
    check H4 "infected, the earlier samples' form (hook runs .vscode/setup.mjs): same result" 1 $? "$WORK/o" \
        "SessionStart (.claude/settings.json): node .vscode/setup.mjs" \
        "! runs when the folder opens (runOn: folderOpen)"

    rm -r "$WORK/inf/node_modules"
    hook-integrity-kit audit --root "$WORK/inf" >"$WORK/o" 2>&1
    check H5 "the package removed: both auto-runs are still there" 1 $? "$WORK/o" \
        "SessionStart (.claude/settings.json): node .claude/setup.mjs" \
        "! runs when the folder opens (runOn: folderOpen)"

    build "$WORK/blessed" --stage clean
    hook-integrity-kit bless --root "$WORK/blessed" --global-dir "$WORK/empty-claude-home" >"$WORK/o" 2>&1
    check H6 "the clean project is blessed (its baseline)" 0 $? "$WORK/o" "Blessed 1 file(s)"
    build "$WORK/blessed" --variant claude
    hook-integrity-kit verify --root "$WORK/blessed" --global-dir "$WORK/empty-claude-home" >"$WORK/o" 2>&1
    check H7 "after infection, verify reports DRIFT: the dropper added, the hooks block changed" 1 $? "$WORK/o" \
        "DRIFT" "ADDED      .claude/setup.mjs" "SETTINGS   \`hooks\` block"
else
    for i in H1 H2 H3 H4 H5 H6 H7; do result SKIP $i "hook-integrity-kit is not on PATH"; done
fi

echo "== injection-screen: is there text aimed at the model?"
if have injection-screen; then
    build "$WORK/is" --variant claude
    injection-screen --provenance untrusted-web --no-session "$WORK/is" >"$WORK/o" 2>&1
    check I1 "every replayed file read as untrusted text: 0 findings (this attack runs code, it does not persuade)" 0 $? "$WORK/o" \
        "findings=0" "NOT:scanned=0 "
else
    result SKIP I1 "injection-screen is not on PATH"
fi

echo "== cti-report-lint: does the write-up claim only what its sources support?"
if have cti-report-lint; then
    if [ -n "${ATTACK_JSON:-}" ]; then
        cti-report-lint check "$HERE/report.md" --attack-json "$ATTACK_JSON" >"$WORK/o" 2>&1
        check_ne C1 "report.md passes, with 2 independent sources behind 3 citations and every technique id checked" 0 $? "$WORK/o" \
            "PASS" "finding[0] CONFIRMED strength 10.0 likelihood 'very likely', 2 independent source(s)"
        cti-report-lint check "$HERE/report.md" --attack-json "$ATTACK_JSON" --json >"$WORK/o" 2>&1
        check_ne C2 "the technique ids were checked against the ATT&CK file, not just counted" 0 $? "$WORK/o" \
            '"checked": true'
    else
        result SKIP C1 "ATTACK_JSON is not set"
        result SKIP C2 "ATTACK_JSON is not set"
    fi
    cti-report-lint check "$HERE/fixtures/overstated-draft.md" >"$WORK/o" 2>&1
    check C3 "the overstated draft is blocked: 'certainly', 'impossible', '95%', no graded evidence" 1 $? "$WORK/o" \
        "BLOCKED" "'certainly'" "'impossible'" "'95%'" "findings: none declared"
else
    for i in C1 C2 C3; do result SKIP $i "cti-report-lint is not on PATH"; done
fi

echo "== ATT&CK: is every mapped technique one MITRE records S9043 using?"
if [ -n "${ATTACK_JSON:-}" ]; then
    "$PY" "$HERE/check_attack.py" "$ATTACK_JSON" "$HERE/report.md" >"$WORK/o" 2>&1
    check_ne A1 "all 8 techniques and the group are in MITRE's own S9043 record" 0 $? "$WORK/o" \
        "9 of 9 mapping claim(s) hold"
else
    result SKIP A1 "ATTACK_JSON is not set"
fi

echo "== publish-gate: is this case study safe to publish?"
if have publish-gate; then
    REPO=$(cd "$HERE/.." && pwd)
    if [ -n "${PUBLISH_GATE_DENYLIST:-}" ]; then deny=""; else deny="--no-denylist"; fi
    # shellcheck disable=SC2086
    publish-gate "$REPO" $deny >"$WORK/o" 2>&1
    check P1 "the repository holds no secret, private address, home path, email or session link${deny:+ (no denylist given)}" 0 $? "$WORK/o" \
        "CLEAN" "self-test: all 12 classes seen"
else
    result SKIP P1 "publish-gate is not on PATH"
fi

echo
echo "$pass reproduced, $fail failed, $skip skipped (of $((pass + fail + skip)) claims)"
[ "$fail" -gt 0 ] && exit 1
[ "$skip" -gt 0 ] && exit 2
exit 0
