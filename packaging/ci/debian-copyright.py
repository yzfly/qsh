#!/usr/bin/env python3
"""Regenerate the vendor/* stanzas of packaging/debian/copyright from Cargo.lock.

    python3 packaging/ci/debian-copyright.py            # rewrite packaging/debian/copyright
    python3 packaging/ci/debian-copyright.py --check    # exit 1 when it is out of date

Run in the top directory of the source tree; needs cargo (`cargo metadata`, which may download
the crates' manifests). One stanza per crate in Cargo.lock, for the directory `cargo vendor
--versioned-dirs` gives it (vendor/NAME-VERSION/), with the crate's authors and its license
expression in Debian's syntax. The License: paragraphs for those names are kept by hand below the
generated stanzas; the script fails when a crate brings a license that has none.
"""

import json
import re
import subprocess
import sys

COPYRIGHT = "packaging/debian/copyright"

# SPDX identifiers whose Debian short name differs.
NAMES = {
    "LGPL-2.1-or-later": "LGPL-2.1+",
    "LGPL-2.1": "LGPL-2.1",
}


def debian_license(spdx: str) -> str:
    """SPDX expression -> DEP-5 License: value (or, and, with ... exception)."""
    expr = spdx.replace("/", " OR ")
    expr = re.sub(r"\s+WITH\s+([A-Za-z0-9.+-]+)-exception", r" with \1 exception", expr)
    expr = re.sub(r"\bOR\b", "or", expr)
    expr = re.sub(r"\bAND\b", "and", expr)
    for spdx_name, name in NAMES.items():
        expr = re.sub(rf"(?<![\w.+-]){re.escape(spdx_name)}(?![\w.+-])", name, expr)
    return re.sub(r"\s+", " ", expr).strip()


def license_names(expr: str) -> set:
    names = set()
    for part in re.split(r"\s+(?:or|and)\s+|[()]", expr):
        part = part.strip()
        if part:
            names.add(part)
    return names


def stanzas() -> tuple:
    meta = json.loads(
        subprocess.run(
            ["cargo", "metadata", "--format-version", "1", "--locked"],
            check=True,
            capture_output=True,
            text=True,
        ).stdout
    )
    out = []
    used = set()
    for p in sorted(meta["packages"], key=lambda p: (p["name"], p["version"])):
        if p["source"] is None:  # the workspace's own crates
            continue
        lic = debian_license(p["license"] or "UNKNOWN")
        used |= license_names(lic)
        authors = [re.sub(r"\s*<[^>]*>", "", a).strip() for a in p.get("authors") or []]
        authors = [a for a in authors if a] or [f"The {p['name']} authors"]
        holders = "\n ".join(authors)
        out.append(
            f"Files: vendor/{p['name']}-{p['version']}/*\n"
            f"Copyright: {holders}\n"
            f"License: {lic}\n"
        )
    return out, used


def main() -> int:
    check = "--check" in sys.argv[1:]
    with open(COPYRIGHT, encoding="utf-8") as f:
        text = f.read()
    # Paragraphs: the header, Files: paragraphs, stand-alone License: paragraphs. The generated
    # ones (Files: vendor/...) go after the last other Files: paragraph.
    paragraphs = [p.strip("\n") + "\n" for p in text.split("\n\n") if p.strip()]
    kept = [p for p in paragraphs if not p.startswith("Files: vendor/")]
    files = [i for i, p in enumerate(kept) if p.startswith("Files:")]
    block, used = stanzas()
    at = files[-1] + 1
    new = "\n".join(kept[:at] + block + kept[at:])
    have = {p.split("\n", 1)[0][len("License: ") :] for p in kept if p.startswith("License:")}
    missing = sorted(n for n in used if n not in have)
    if missing:
        print(f"{COPYRIGHT}: no License: paragraph for {', '.join(missing)}", file=sys.stderr)
        return 1
    if check:
        if new != text:
            print(f"{COPYRIGHT} is out of date: run {sys.argv[0]}", file=sys.stderr)
            return 1
        return 0
    with open(COPYRIGHT, "w", encoding="utf-8") as f:
        f.write(new)
    return 0


if __name__ == "__main__":
    sys.exit(main())
