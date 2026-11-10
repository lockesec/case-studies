"""Fetch the published attack texts from their primary sources, and check each is the text this
study was written against.

    python3 fetch_corpus.py OUTDIR

The texts are not copied into this repository: one has no licence and the others belong to
their authors. Each is fetched, extracted exactly as published, and compared with a SHA-256
recorded when the study was written. A text that cannot be fetched, or no longer matches,
is NOT EVALUABLE: the claims about it are not shown, never passed. Standard library only;
nothing fetched is executed (the Python file is parsed, not imported).

Exit 0: all three written. 2: at least one could not be fetched or has changed (named).
"""
from __future__ import annotations

import ast
import hashlib
import html
import json
import os
import re
import sys
import urllib.parse
import urllib.request
from pathlib import Path

UA = {"User-Agent": "case-studies/fetch_corpus (defensive research; reads public pages)"}


class _DropAuthOffHost(urllib.request.HTTPRedirectHandler):
    """urllib keeps request headers across a redirect; never carry the token to another host."""

    def redirect_request(self, req, fp, code, msg, headers, newurl):
        new = super().redirect_request(req, fp, code, msg, headers, newurl)
        if new is not None and urllib.parse.urlsplit(newurl).hostname != "api.github.com":
            new.remove_header("Authorization")
        return new


def _get(url: str) -> bytes:
    headers = dict(UA)
    token = os.environ.get("GITHUB_TOKEN")
    # The token goes to api.github.com only (anonymous calls are limited to 60 an hour per
    # address, which shared CI runners use up), never to any other host.
    if token and urllib.parse.urlsplit(url).hostname == "api.github.com":
        headers["Authorization"] = f"Bearer {token}"
    req = urllib.request.Request(headers=headers, url=url)
    opener = urllib.request.build_opener(_DropAuthOffHost)
    with opener.open(req, timeout=30) as r:          # fixed https URLs
        return r.read()


def supabase_ticket() -> str:
    """General Analysis, 2025-07: the support-ticket text, from the page's code block."""
    page = _get("https://www.generalanalysis.com/blog/supabase-mcp-blog").decode("utf-8")
    m = re.search(r'<code class="hljs language-text">(This message is directed at CLAUDE.*?)</code>',
                  page, re.S)
    if not m:
        raise ValueError("the payload code block was not found on the page")
    return html.unescape(m.group(1))


def tool_description() -> str:
    """Invariant Labs, 2025-04: the `add` tool's docstring, at a pinned commit."""
    src = _get("https://raw.githubusercontent.com/invariantlabs-ai/mcp-injection-experiments/"
               "7382a5e64d825b2c7c2bace11f8fb9f2f16e01e2/direct-poisoning.py").decode("utf-8")
    fn = next(n for n in ast.walk(ast.parse(src)) if isinstance(n, ast.FunctionDef) and n.name == "add")
    return ast.get_docstring(fn, clean=False) or ""


def github_issue() -> str:
    """Invariant Labs, 2025-05: the public issue that hijacked the agent, title and body."""
    d = json.loads(_get("https://api.github.com/repos/ukend0464/pacman/issues/1"))
    return d["title"] + "\n\n" + d["body"]


SOURCES = {
    "supabase-ticket.txt": (supabase_ticket,
                            "162a9f3ed7fe352f432ca9f74b19674568830c842a34388530b686e69d181d52"),
    "add-tool-description.txt": (tool_description,
                                 "57f39b2f799cd75c6ec679d31581023e57ef31b8b28278a9d230bd95b81d50bd"),
    "github-issue.md": (github_issue,
                        "561683d235d234e8c75b73b36ee54616bf15d183d30d7964f16e1b1a3085c3c2"),
}


def main(argv: list) -> int:
    if len(argv) != 1:
        print(__doc__)
        return 64
    out = Path(argv[0])
    out.mkdir(parents=True, exist_ok=True)
    bad = []
    for name, (fetch, want) in SOURCES.items():
        try:
            text = fetch()
        except Exception as e:                       # network, layout or parse: all mean "not seen"
            bad.append(f"{name}: could not be fetched ({e.__class__.__name__}: {e})")
            continue
        got = hashlib.sha256(text.encode("utf-8")).hexdigest()
        if got != want:
            bad.append(f"{name}: the source has changed since the study was written "
                       f"(sha256 {got[:16]}..., expected {want[:16]}...)")
            continue
        (out / name).write_text(text, encoding="utf-8")
        print(f"ok  {name} ({len(text)} chars, sha256 {got[:16]}...)")
    for b in bad:
        print(f"NOT EVALUABLE: {b}")
    return 2 if bad else 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
