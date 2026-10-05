<div align="center">

# osv-dedupe

**Check whether a security finding already matches a published OSV/NVD advisory — before you spend time triaging it.**

[![PyPI](https://img.shields.io/pypi/v/osv-dedupe?color=blue)](https://pypi.org/project/osv-dedupe/)
[![Python](https://img.shields.io/pypi/pyversions/osv-dedupe)](https://pypi.org/project/osv-dedupe/)
[![License: MIT](https://img.shields.io/badge/license-MIT-green)](LICENSE)
[![Downloads](https://static.pepy.tech/badge/osv-dedupe/month)](https://pepy.tech/project/osv-dedupe)

</div>

---

Given a security finding for a PyPI package, decide whether it's **already a
published vulnerability** before you spend time (or LLM tokens) triaging it.
`osv-dedupe` queries [OSV](https://osv.dev) (and optionally
[NVD](https://nvd.nist.gov)), then scores each candidate advisory against your
finding using source reliability, package-name presence, CWE overlap, and
file/function hints.

## Highlights

- Queries OSV (and optionally NVD) for the package and version
- Transparent, weighted confidence score per candidate advisory
- Matches on CWE, package name and file/function hints
- Best-effort networking: unreachable APIs return `[]`, never raise

## Install

```bash
pip install osv-dedupe
```

## Library usage

```python
from osv_dedupe import find_known_advisory_matches

finding = {"cwe": "CWE-22", "path": "demo/tarfile_utils.py"}
matches = find_known_advisory_matches("demo", "1.0.0", finding)

for m in matches:
    print(m["confidence"], m["source"], m["id"], m["url"])
    print(m["reason"])
```

Each match is a dict with `source`, `id`, `url`, `confidence` (0.0–1.0),
`reason`, `aliases`, `cwes`, and `summary`. A confidence `>= 0.70` is generally
strong enough to treat the finding as already reported.

Options:

- `min_confidence` (default `0.70`) — threshold for returned matches.
- `include_nvd` (default `False`) — also keyword-search NVD (slower, noisier).
- `limit` (default `3`) — max matches returned.

## CLI

```bash
osv-dedupe requests 2.0.0 --cwe CWE-22
osv-dedupe django 3.2 --include-nvd --json
```

## Scoring

| Signal | Weight |
| --- | --- |
| OSV returned the advisory | +0.45 |
| NVD keyword hit | +0.30 |
| Package name in advisory text | +0.15 |
| CWE matches finding | +0.25 |
| CWE differs | −0.10 |
| File/function hint appears | +0.10 |

Confidence is clamped to `[0.0, 1.0]`. All network calls are best-effort: if OSV
or NVD are unreachable, you get an empty list, never an exception. Results are
cached in-process; call `clear_cache()` to reset.

## Development

```bash
git clone https://github.com/rahulreddykarne/osv-dedupe.git
cd osv-dedupe
python -m venv .venv && source .venv/bin/activate   # Windows: .venv\Scripts\activate
pip install -e ".[dev]"
python -m build
```

Bug reports and pull requests are welcome on the [issue tracker](https://github.com/rahulreddykarne/osv-dedupe/issues).

## Related projects

Part of a small toolkit for Python supply-chain security research:

| Project | What it does |
| --- | --- |
| [pypi-bulk-download](https://github.com/rahulreddykarne/pypi-bulk-download) | Bulk-download top PyPI packages in parallel with safe unpacking. |
| [tarslip-guard](https://github.com/rahulreddykarne/tarslip-guard) | Detect unsafe extractall() calls and safely extract tar/zip archives. |
| [pypi-version-bisect](https://github.com/rahulreddykarne/pypi-version-bisect) | Find a vulnerability's affected version range in O(log n) checks. |
| [pypi-blast-radius](https://github.com/rahulreddykarne/pypi-blast-radius) | Estimate the downstream impact of a PyPI package version. |
| [installtime-audit](https://github.com/rahulreddykarne/installtime-audit) | Flag install-time side effects in setup.py and friends. |
| [cvss-estimator](https://github.com/rahulreddykarne/cvss-estimator) | CVSS v3.1 calculator and evidence-driven vector estimator. |

## License

Released under the [MIT License](LICENSE).
