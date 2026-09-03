"""G4 -- exact-match merchant pinning.

Mitigates: Attack 4, merchant substitution / typo-squatting.
Threat family F3 (Trust-Root Subversion), threat T-27.

Any comparison looser than byte equality -- casefolding, Unicode
normalisation, substring, edit-distance "did you mean" matching -- turns the
allowlist into a suggestion. `merchant_a1pha` (digit one) is not
`merchant_alpha` (letter ell), and no amount of helpfulness should make it so.
"""
from __future__ import annotations

import unicodedata
from difflib import SequenceMatcher


def exact_match(candidate: str, allowlist: list[str]) -> bool:
    """Byte-for-byte membership test. No normalisation of any kind.

    Fails closed: an unknown merchant is rejected, never approximated.
    """
    return candidate in allowlist


def fuzzy_match(candidate: str, allowlist: list[str], threshold: float = 0.85) -> bool:
    """The VULNERABLE comparison. Present only so the attack has something to beat.

    This is not a strawman: case-insensitive matching with Unicode
    normalisation and a similarity fallback is a common convenience in real
    merchant-resolution code. It is exactly what T-27 exploits.
    """
    norm = unicodedata.normalize("NFKD", candidate).casefold().strip()
    for allowed in allowlist:
        allowed_norm = unicodedata.normalize("NFKD", allowed).casefold().strip()
        if norm == allowed_norm:
            return True
        if norm in allowed_norm or allowed_norm in norm:
            return True
        if SequenceMatcher(None, norm, allowed_norm).ratio() >= threshold:
            return True
    return False


def confusable_report(candidate: str, allowlist: list[str]) -> str:
    """Explain WHY a near-miss was rejected, for the audit log."""
    best, score = None, 0.0
    for allowed in allowlist:
        ratio = SequenceMatcher(None, candidate, allowed).ratio()
        if ratio > score:
            best, score = allowed, ratio
    if best is None:
        return f"'{candidate}' matches nothing in the pinned allowlist"
    return (
        f"'{candidate}' is not in the pinned allowlist; closest entry is "
        f"'{best}' at {score:.0%} similarity -- rejected (exact match required)"
    )
