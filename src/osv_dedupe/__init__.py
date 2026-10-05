"""osv-dedupe: is this PyPI finding already a published OSV/NVD advisory?

Public API
----------
- :func:`find_known_advisory_matches` – scored advisory overlaps for a finding.
- :class:`AdvisoryMatch` – a single scored match.
- :func:`clear_cache` – drop the in-process advisory cache.
"""

from __future__ import annotations

from ._core import AdvisoryMatch, clear_cache, find_known_advisory_matches

__all__ = ["find_known_advisory_matches", "AdvisoryMatch", "clear_cache"]
__version__ = "0.1.0"
