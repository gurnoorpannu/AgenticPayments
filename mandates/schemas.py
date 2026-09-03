"""Pydantic models for the four mandate types (simplified AP2 v0.2).

Simplification, stated honestly: these are plain ES256 JWTs. Real AP2 uses
SD-JWT with selective disclosure; we do not implement selective disclosure.
See README "What we did NOT solve".
"""
from __future__ import annotations

import uuid
from datetime import datetime, timedelta, timezone
from typing import Any, Literal, Optional

from pydantic import BaseModel, Field


def _uuid() -> str:
    return str(uuid.uuid4())


def _now_ts() -> int:
    return int(datetime.now(timezone.utc).timestamp())


def iso_in(seconds: int) -> str:
    return (datetime.now(timezone.utc) + timedelta(seconds=seconds)).isoformat()


def parse_iso(value: str) -> datetime:
    dt = datetime.fromisoformat(value)
    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=timezone.utc)
    return dt


# --- cart -------------------------------------------------------------------
class CartItem(BaseModel):
    product_id: str
    name: str
    unit_price_paise: int
    quantity: int = 1
    category: str
    merchant_id: str

    @property
    def line_total_paise(self) -> int:
        return self.unit_price_paise * self.quantity

    def canonical(self) -> dict[str, Any]:
        """The fields that are bound into checkout_hash.

        Free-text fields (description) are excluded on purpose -- the hash
        commits to the *commercial terms*, not to marketing copy.
        """
        return {
            "product_id": self.product_id,
            "name": self.name,
            "unit_price_paise": self.unit_price_paise,
            "quantity": self.quantity,
            "category": self.category,
            "merchant_id": self.merchant_id,
        }


class Cart(BaseModel):
    session_id: str
    items: list[CartItem] = Field(default_factory=list)

    @property
    def total_paise(self) -> int:
        return sum(i.line_total_paise for i in self.items)

    @property
    def merchant_ids(self) -> list[str]:
        return sorted({i.merchant_id for i in self.items})

    @property
    def categories(self) -> list[str]:
        return sorted({i.category for i in self.items})

    def canonical(self) -> dict[str, Any]:
        """Canonical cart representation -- the pre-image of checkout_hash."""
        return {
            "session_id": self.session_id,
            "items": [i.canonical() for i in self.items],
            "total_paise": self.total_paise,
        }


# --- constraints ------------------------------------------------------------
class CheckoutConstraints(BaseModel):
    """The user's actual intent. This is the ground truth the guard defends."""

    max_amount_paise: int
    allowed_merchants: list[str]
    allowed_categories: list[str]
    expires_at: str


class PaymentConstraints(BaseModel):
    max_amount_paise: int
    allowed_payees: list[str]
    step_up_threshold_paise: int
    expires_at: str


# --- mandates ---------------------------------------------------------------
class OpenCheckoutMandate(BaseModel):
    """Signed by the USER key at session start. Delegates shopping authority."""

    type: Literal["open_checkout"] = "open_checkout"
    session_id: str
    constraints: CheckoutConstraints
    agent_pk: str
    iat: int = Field(default_factory=_now_ts)
    jti: str = Field(default_factory=_uuid)


class OpenPaymentMandate(BaseModel):
    """Signed by the USER key. Payment-side limits and allowed payees."""

    type: Literal["open_payment"] = "open_payment"
    session_id: str
    constraints: PaymentConstraints
    agent_pk: str
    iat: int = Field(default_factory=_now_ts)
    jti: str = Field(default_factory=_uuid)


class ClosedCheckoutMandate(BaseModel):
    """Signed by the AGENT key once the cart is final."""

    type: Literal["closed_checkout"] = "closed_checkout"
    parent_jti: str
    session_id: str
    #: The constraints the AGENT believes apply. This is agent-asserted context,
    #: derived from tool output and catalog text -- none of which is signed by
    #: the user. The naive verifier trusts it; the guard ignores it entirely and
    #: reads the user-signed open mandate instead. This field IS threat T-1.
    asserted_constraints: Optional[CheckoutConstraints] = None
    checkout_hash: str
    amount_paise: int
    merchant_id: str
    iat: int = Field(default_factory=_now_ts)
    jti: str = Field(default_factory=_uuid)
    nonce: str = Field(default_factory=_uuid)
    expires_at: str = Field(default_factory=lambda: iso_in(600))


class RiskData(BaseModel):
    """Risk signals asserted about a transaction.

    In the VULNERABLE path this travels unsigned alongside the mandate and the
    verifier reads it directly -- that is threat T-34. In the GUARDED path it
    is only accepted inside a RiskAttestation signed by the Trusted Surface.
    """

    risk_score: Literal["low", "medium", "high"]
    step_up_completed: bool
    method: str
    transaction_id: Optional[str] = None


class RiskAttestation(BaseModel):
    """Signed wrapper around RiskData, issued by the Trusted Surface (G3)."""

    type: Literal["risk_attestation"] = "risk_attestation"
    issuer: str
    transaction_id: str
    risk: RiskData
    iat: int = Field(default_factory=_now_ts)
    jti: str = Field(default_factory=_uuid)
    expires_at: str = Field(default_factory=lambda: iso_in(300))


class ClosedPaymentMandate(BaseModel):
    """Signed by the AGENT key.

    `transaction_id` MUST equal the closed checkout mandate's `checkout_hash`
    -- that binding is what ties the money to the specific cart.
    """

    type: Literal["closed_payment"] = "closed_payment"
    parent_jti: str
    session_id: str
    transaction_id: str
    amount_paise: int
    payee_id: str
    risk_data: Optional[RiskData] = None
    risk_attestation_jwt: Optional[str] = None
    iat: int = Field(default_factory=_now_ts)
    jti: str = Field(default_factory=_uuid)
    nonce: str = Field(default_factory=_uuid)
    expires_at: str = Field(default_factory=lambda: iso_in(600))


# --- results ----------------------------------------------------------------
class CheckResult(BaseModel):
    """One named decision made by the verifier or the guard."""

    check: str
    passed: bool
    guard: Optional[str] = None
    detail: str = ""


class VerificationOutcome(BaseModel):
    authorized: bool
    checks: list[CheckResult] = Field(default_factory=list)
    failed_guard: Optional[str] = None
    reason: str = ""
    step_up_required: bool = False

    def add(self, check: str, passed: bool, detail: str = "", guard: str | None = None) -> "VerificationOutcome":
        self.checks.append(CheckResult(check=check, passed=passed, guard=guard, detail=detail))
        if not passed and self.authorized:
            self.authorized = False
            self.failed_guard = guard
            self.reason = f"{check}: {detail}"
        return self
