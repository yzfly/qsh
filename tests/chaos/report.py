#!/usr/bin/env python3
"""Render the JSON lines of crates/qsh-cli/tests/chaos.rs as Markdown.

Usage: report.py RESULTS.jsonl...

Checks and measurements become one table per scenario; benchmark cells (kind "bench") become
the table of docs/m2.md section 12.4, one column per tool. The output is for the job summary and
the workflow artifacts; publishing the benchmark anywhere else needs the maintainer's approval.
"""

import json
import os
import sys

BENCH_ROWS = [
    ("echo", "Keystroke echo, p50 (mosh: prediction off / on)"),
    ("ctrl_c", "Ctrl-C during `yes`, time to the prompt, p50"),
    ("seq", "`seq 1 N` to the end of its output"),
    ("address_change", "Client address change; time to output"),
    ("udp_block", "UDP blocked mid-session; time to output"),
    ("outage", "Network outage; time to output after it, lines missed"),
    ("bulk", "Bulk pipe transfer (`cat` of 100 MB)"),
    ("scrollback", "Scrollback after the flood"),
]
TOOLS = ["ssh", "mosh", "qsh"]


def cell(value):
    if value is None:
        return "—"
    if isinstance(value, (dict, list)):
        return "`" + json.dumps(value, separators=(",", ":")) + "`"
    return str(value).replace("|", "\\|")


def main(paths):
    records = []
    for path in paths:
        try:
            with open(path, encoding="utf-8") as f:
                for line in f:
                    line = line.strip()
                    if line:
                        try:
                            records.append(json.loads(line))
                        except ValueError:
                            pass
        except OSError as e:
            print(f"report.py: {e}", file=sys.stderr)
    out = []
    env = next((r for r in records if r.get("kind") == "env"), None)
    commit = (env or {}).get("commit") or os.environ.get("GITHUB_SHA", "")
    if env:
        out.append(
            f"Environment: {env.get('qsh')}; {env.get('ssh')}; {env.get('mosh')}; "
            f"kernel {env.get('kernel')}" + (f"; commit {commit[:12]}" if commit else "")
        )
        out.append("")

    checks = [r for r in records if r.get("kind") in ("check", "measure")]
    if checks:
        hard_fail = [r for r in checks if r.get("kind") == "check" and not r.get("ok") and r.get("hard")]
        soft_fail = [r for r in checks if r.get("kind") == "check" and not r.get("ok") and not r.get("hard")]
        passed = [r for r in checks if r.get("kind") == "check" and r.get("ok")]
        out.append(
            f"## Chaos: {len(passed)} passed, {len(hard_fail)} failed, "
            f"{len(soft_fail)} report-only failures"
        )
        out.append("")
        scenarios = []
        for r in checks:
            if r.get("scenario") not in scenarios:
                scenarios.append(r.get("scenario"))
        for scenario in scenarios:
            out.append(f"### {scenario}")
            out.append("")
            out.append("| Profile | Metric | Value | Limit | Result |")
            out.append("|---|---|---|---|---|")
            for r in checks:
                if r.get("scenario") != scenario:
                    continue
                if r["kind"] == "measure":
                    result = "measured"
                    limit = r.get("unit") or ""
                elif r.get("ok"):
                    result = "pass"
                    limit = r.get("limit", "")
                elif r.get("hard"):
                    result = "**FAIL**"
                    limit = r.get("limit", "")
                else:
                    result = f"report-only: fails until {r.get('until')}"
                    limit = r.get("limit", "")
                out.append(
                    f"| {cell(r.get('profile'))} | {cell(r.get('metric'))} | {cell(r.get('value'))} "
                    f"| {cell(limit)} | {result} |"
                )
            out.append("")

    bench = [r for r in records if r.get("kind") == "bench"]
    if bench:
        profile = bench[0].get("profile", "")
        out.append(f"## Benchmark: {profile}" + (f" (commit {commit[:12]})" if commit else ""))
        out.append("")
        out.append("| " + profile + " | " + " | ".join(TOOLS) + " |")
        out.append("|---|" + "---|" * len(TOOLS))
        for key, label in BENCH_ROWS:
            if key == "seq":
                lines = next((r["value"].get("lines") for r in bench if r.get("row") == "seq"
                              and isinstance(r.get("value"), dict)), None)
                if lines:
                    label = f"`seq 1 {lines}` to the end of its output"
            cells = []
            for tool in TOOLS:
                r = next((r for r in bench if r.get("row") == key and r.get("tool") == tool), None)
                cells.append(cell(r.get("text")) if r else "not run")
            out.append(f"| {label} | " + " | ".join(cells) + " |")
        out.append("")
        out.append(
            "Measured by `tests/chaos/bench.sh` in the netns topology of `tests/chaos/netns.sh`; "
            "times from the keystroke (or network event) to the bytes on the client's terminal."
        )
        out.append("")
    print("\n".join(out))


if __name__ == "__main__":
    main(sys.argv[1:])
