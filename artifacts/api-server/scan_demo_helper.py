#!/usr/bin/env python3
"""
Minimal stdin→stdout wrapper around killswitch_ai.core.scanner.
Reads raw text from stdin, writes JSON findings to stdout.
Input content is never logged or persisted.
"""
import json
import sys

from killswitch_ai.core.scanner import scan_text


def main() -> None:
    text = sys.stdin.read()
    findings = scan_text(text, path="demo")

    output = []
    for f in findings:
        output.append({
            "finding_id": f.finding_id,
            "severity": f.severity,
            "category": f.category,
            "finding_type": f.finding_type,
            "description": f.description,
            "recommendation": f.recommendation,
            "match_start": f.match_start,
            "match_end": f.match_end,
        })

    sys.stdout.write(json.dumps(output))


if __name__ == "__main__":
    main()
