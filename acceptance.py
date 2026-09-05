"""The acceptance layer: MandateGuard exposed as an integrable service.

This is the "system that accepts agentic payments" -- the same guarded
pipeline the attack scenarios run against, behind a stable HTTP surface a
merchant or an external agent can actually call.

Two steps, mirroring how AP2 splits authority:

    POST /v1/session    the user states intent; the guard captures consent
                        faithfully and the USER key signs the open mandates
    POST /v1/authorize  the agent submits a cart; the independent verifier
                        runs every check and money moves only if it holds

Honest simplification: in a real deployment the shopping agent holds its own
private key and submits mandates it signed itself. Here the service signs on
the agent's behalf, because the agent and the service run in one process. The
security properties being demonstrated -- faithful consent capture, single-use
nonces, signed risk attestation, exact merchant pinning, independent
verification -- do not depend on that split.
"""
from __future__ import annotations

import threading
from typing import Any, Optional

from pydantic import BaseModel, Field

from agent.session import ShoppingSession
from config import Mode, Settings, get_settings
from mandates.schemas import ConstraintProposal, RiskData, UserIntent


class SessionRequest(BaseModel):
    goal: str = "buy running shoes"
    budget_paise: int = Field(200_000, gt=0)
    merchants: list[str] = Field(default_factory=lambda: ["merchant_alpha"])
    categories: list[str] = Field(default_factory=lambda: ["footwear"])
    step_up_threshold_paise: int = 150_000
    mode: str = "guarded"
    #: When true, the agent surveys the catalog and proposes its own ceiling
    #: before consent is captured -- the AM1 window.
    agent_proposes_constraints: bool = False


class CartLine(BaseModel):
    product_id: str
    quantity: int = Field(1, ge=1)


class AuthorizeRequest(BaseModel):
    session_id: str
    items: list[CartLine]
    merchant_id: Optional[str] = None
    payee_id: Optional[str] = None
    #: Set false to simulate an agent skipping the step-up challenge.
    perform_step_up: bool = True
    #: An agent asserting its own risk verdict, unsigned. Rejected when guarded.
    self_asserted_risk: Optional[RiskData] = None


class _Store:
    """In-memory session registry. Process-local; not for production."""

    def __init__(self) -> None:
        self._lock = threading.Lock()
        self._sessions: dict[str, ShoppingSession] = {}

    def put(self, session: ShoppingSession) -> None:
        with self._lock:
            self._sessions[session.session_id] = session

    def get(self, session_id: str) -> Optional[ShoppingSession]:
        with self._lock:
            return self._sessions.get(session_id)


STORE = _Store()


def open_session(req: SessionRequest, settings: Optional[Settings] = None) -> tuple[ShoppingSession, dict[str, Any]]:
    """Capture consent and mint the user-signed open mandates."""
    settings = settings or get_settings()
    mode = Mode(req.mode)
    intent = UserIntent(
        goal=req.goal, budget_paise=req.budget_paise,
        merchants=list(req.merchants), categories=list(req.categories),
    )

    proposal: Optional[ConstraintProposal] = None
    if req.agent_proposes_constraints:
        from agent.shopping_agent import DeterministicAgent
        from catalog.service import CatalogService
        proposal = DeterministicAgent().propose_constraints(intent, CatalogService())

    session = ShoppingSession(
        settings=settings, mode=mode, intent=intent,
        step_up_threshold_paise=req.step_up_threshold_paise,
        constraint_proposal=proposal,
    )
    STORE.put(session)

    render = session.approval_render
    return session, {
        "session_id": session.session_id,
        "mode": mode.value,
        "user_stated_budget_paise": intent.budget_paise,
        "approval": {
            "displayed_cap_paise": render.displayed_cap_paise,
            "signed_cap_paise": render.signed_cap_paise,
            "faithful": render.faithful,
            "rendered_by": render.rendered_by,
            "justification_shown": render.justification_shown,
        },
        "agent_proposed_cap_paise": proposal.max_amount_paise if proposal else None,
        "constraints": session.checkout_constraints.model_dump(),
        "consent_detail": session.consent.detail,
        # The user-signed mandates. A real agent would receive these and sign
        # its own closed mandates against them.
        "open_checkout_jwt": session.open_checkout_jwt,
        "open_payment_jwt": session.open_payment_jwt,
    }


def authorize(req: AuthorizeRequest) -> dict[str, Any]:
    """Run the full guarded pipeline over a submitted cart."""
    session = STORE.get(req.session_id)
    if session is None:
        raise KeyError(req.session_id)

    session.cart.items.clear()
    unknown: list[str] = []
    for line in req.items:
        message = session.add_to_cart(line.product_id, line.quantity)
        if message.startswith("error:"):
            unknown.append(line.product_id)
    if unknown:
        return {"authorized": False, "declined_reason": f"unknown product(s): {', '.join(unknown)}",
                "guard": None, "step_up_required": False, "checks": [], "order": None}

    result = session.checkout(
        merchant_id=req.merchant_id,
        payee_id=req.payee_id,
        perform_step_up=req.perform_step_up,
        forged_risk_data=req.self_asserted_risk,
    )
    return {
        "authorized": result.authorized,
        "declined_reason": None if result.authorized else result.outcome.reason,
        "guard": result.outcome.failed_guard,
        "step_up_required": result.step_up_required,
        "cart_total_paise": session.cart.total_paise,
        "checkout_hash": result.checkout_hash,
        "checks": [c.model_dump() for c in result.outcome.checks],
        "order": None if not result.order else {
            "order_id": result.order.order_id,
            "amount_paise": result.order.amount_paise,
            "currency": result.order.currency,
            "status": result.order.status,
            "provenance": result.order.provenance,
        },
    }
