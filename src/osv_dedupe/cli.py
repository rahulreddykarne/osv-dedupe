"""Command-line interface for osv-dedupe."""

from __future__ import annotations

import argparse
import json
import sys

from ._core import find_known_advisory_matches


def _build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="osv-dedupe",
        description="Check whether a PyPI finding overlaps a known OSV/NVD advisory.",
    )
    parser.add_argument("package", help="PyPI package name")
    parser.add_argument("version", nargs="?", default="", help="affected version (optional)")
    parser.add_argument("--cwe", default="", help="finding CWE, e.g. CWE-22")
    parser.add_argument("--path", default="", help="finding file path (optional hint)")
    parser.add_argument("--min-confidence", type=float, default=0.70)
    parser.add_argument("--include-nvd", action="store_true", help="also query NVD (slower)")
    parser.add_argument("--json", action="store_true", help="emit raw JSON")
    return parser


def main(argv: list[str] | None = None) -> int:
    args = _build_parser().parse_args(argv)
    finding = {"cwe": args.cwe, "path": args.path}
    matches = find_known_advisory_matches(
        args.package,
        args.version,
        finding,
        min_confidence=args.min_confidence,
        include_nvd=args.include_nvd,
    )
    if args.json:
        print(json.dumps(matches, indent=2))
        return 0 if matches else 1
    if not matches:
        print(f"No known advisory match >= {args.min_confidence} for {args.package}")
        return 1
    for m in matches:
        print(f"[{m['confidence']:.2f}] {m['source']} {m['id']}  {m['url']}")
        print(f"        {m['reason']}")
    return 0


if __name__ == "__main__":  # pragma: no cover
    raise SystemExit(main())
