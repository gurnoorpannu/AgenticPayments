"""Attack scenarios against the mandate pipeline.

Every scenario returns the same structured result so the scorecard can be
generated mechanically from real runs. No number in results/scorecard.json is
written by hand.
"""
from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Optional

from config import Mode


@dataclass
class AttackResult:
    name: str
    threat_ref: str
    mode: str
    succeeded: bool
    evidence: str
    guard_that_blocked: Optional[str] = None
    order_id: Optional[str] = None
    order_provenance: Optional[str] = None
    agent_kind: Optional[str] = None
    #: The verifier's full named check pipeline, so a UI can show WHERE a
    #: run stopped -- or, in vulnerable mode, that nothing stopped it.
    checks: list[dict[str, Any]] = field(default_factory=list)
    detail: dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        return {
            "name": self.name,
            "threat_ref": self.threat_ref,
            "mode": self.mode,
            "succeeded": self.succeeded,
            "evidence": self.evidence,
            "guard_that_blocked": self.guard_that_blocked,
            "order_id": self.order_id,
            "order_provenance": self.order_provenance,
            "agent_kind": self.agent_kind,
            "checks": self.checks,
            "detail": self.detail,
        }


@dataclass
class LegitResult:
    """Outcome of a scenario that SHOULD be allowed through in guarded mode.

    A guard that fails closed on everything blocks 16/16 attacks and is
    useless. These scenarios measure the other half of the question: does the
    guard wrongly stop real customers? Every one of them sits on a boundary
    where a fail-closed check is most likely to over-fire.
    """

    name: str
    guard_under_test: str
    intent: str
    allowed: bool
    evidence: str
    blocked_by: Optional[str] = None
    order_id: Optional[str] = None
    order_provenance: Optional[str] = None
    checks: list[dict[str, Any]] = field(default_factory=list)
    detail: dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        return {
            "name": self.name,
            "guard_under_test": self.guard_under_test,
            "intent": self.intent,
            "allowed": self.allowed,
            "evidence": self.evidence,
            "blocked_by": self.blocked_by,
            "order_id": self.order_id,
            "order_provenance": self.order_provenance,
            "checks": self.checks,
            "detail": self.detail,
        }


def checks_of(outcome) -> list[dict[str, Any]]:
    """Flatten a VerificationOutcome's named checks for transport to a UI."""
    return [c.model_dump() for c in outcome.checks]


def mode_of(mode: Mode | str) -> str:
    return mode.value if isinstance(mode, Mode) else str(mode)
