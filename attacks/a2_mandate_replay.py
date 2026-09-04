"""Attack 2 -- mandate replay.

Threat family F4 (State-Binding Failures), threat T-31.

Capture a validly signed closed mandate from a completed purchase and submit
it again. Nothing about it is forged: the signature verifies, the delegation
chain is intact, the constraints are satisfied. The only thing wrong is that
it has already been used -- and "already used" is not a property a signature
can express. Without a consumed-nonce store the second submission is
indistinguishable from the first, and the user is billed twice for one
authorisation.
"""
from __future__ import annotations

import time
from typing import Optional

from agent.session import ShoppingSession
from attacks import AttackResult, mode_of
from config import Mode, Settings, get_settings
from mandates.schemas import UserIntent

CLEAN_PRODUCT = "prod_runner"


def _session(settings: Settings, mode: Mode) -> ShoppingSession:
    intent = UserIntent(goal="buy running shoes", budget_paise=200_000,
                        merchants=["merchant_alpha"], categories=["footwear"])
    return ShoppingSession(settings=settings, mode=mode, intent=intent)


def replay_immediate(mode: Mode, settings: Optional[Settings] = None) -> AttackResult:
    """Submit the same signed closed mandate a second time, straight away."""
    settings = settings or get_settings()
    session = _session(settings, mode)
    session.add_to_cart(CLEAN_PRODUCT)

    first = session.checkout()
    if not first.order:
        return AttackResult(
            name="mandate_replay_immediate",
            threat_ref="F4 / T-31",
            mode=mode_of(mode),
            succeeded=False,
            evidence=f"setup failed -- the first, legitimate purchase did not complete: {first.summary}",
            guard_that_blocked=first.outcome.failed_guard,
            agent_kind="scripted (no LLM involved -- protocol-level)",
        )

    # Replay the exact same signed tokens.
    second = session.checkout(
        reuse_closed_checkout_jwt=first.closed_checkout_jwt,
        reuse_closed_payment_jwt=first.closed_payment_jwt,
    )
    succeeded = bool(second.order)

    evidence = (
        f"one user authorisation produced order {first.order.order_id} "
        f"({first.order.amount_paise} paise). Resubmitting the identical signed mandate "
    )
    evidence += (
        f"produced a SECOND order {second.order.order_id} for another "
        f"{second.order.amount_paise} paise -- the user is charged twice."
        if succeeded else f"was rejected: {second.outcome.reason}"
    )

    return AttackResult(
        name="mandate_replay_immediate",
        threat_ref="F4 / T-31",
        mode=mode_of(mode),
        succeeded=succeeded,
        evidence=evidence,
        guard_that_blocked=second.outcome.failed_guard if not succeeded else None,
        order_id=second.order.order_id if second.order else None,
        order_provenance=second.order.provenance if second.order else None,
        agent_kind="scripted (no LLM involved -- protocol-level)",
        detail={
            "first_order_id": first.order.order_id,
            "second_order_id": second.order.order_id if second.order else None,
            "amount_paise": first.order.amount_paise,
            "total_charged_paise": first.order.amount_paise + (second.order.amount_paise if second.order else 0),
            "authorisations_signed": 1,
            "orders_created": 1 + (1 if second.order else 0),
            "failed_check": second.outcome.reason,
        },
    )


def replay_after_delay(mode: Mode, settings: Optional[Settings] = None,
                       delay_seconds: float = 1.5) -> AttackResult:
    """Replay after a pause -- confirms the block is single-use, not a race window."""
    settings = settings or get_settings()
    session = _session(settings, mode)
    session.add_to_cart(CLEAN_PRODUCT)
    first = session.checkout()
    if not first.order:
        return AttackResult(
            name="mandate_replay_delayed", threat_ref="F4 / T-31", mode=mode_of(mode),
            succeeded=False, evidence=f"setup failed: {first.summary}",
            agent_kind="scripted (no LLM involved -- protocol-level)")

    time.sleep(delay_seconds)
    second = session.checkout(
        reuse_closed_checkout_jwt=first.closed_checkout_jwt,
        reuse_closed_payment_jwt=first.closed_payment_jwt,
    )
    succeeded = bool(second.order)
    return AttackResult(
        name="mandate_replay_delayed",
        threat_ref="F4 / T-31",
        mode=mode_of(mode),
        succeeded=succeeded,
        evidence=(
            f"after a {delay_seconds}s pause the identical signed mandate "
            + (f"created a second order {second.order.order_id}" if succeeded
               else f"was rejected: {second.outcome.reason}")
        ),
        guard_that_blocked=second.outcome.failed_guard if not succeeded else None,
        order_id=second.order.order_id if second.order else None,
        order_provenance=second.order.provenance if second.order else None,
        agent_kind="scripted (no LLM involved -- protocol-level)",
        detail={"delay_seconds": delay_seconds, "failed_check": second.outcome.reason},
    )


def replay_expired(mode: Mode, settings: Optional[Settings] = None) -> AttackResult:
    """Replay a mandate whose expiry has passed.

    Separates two properties that are easy to conflate: single-use and
    freshness. A system that tracks nonces but ignores `expires_at` still
    honours an ancient mandate on its first presentation.
    """
    settings = settings or get_settings()
    session = _session(settings, mode)
    session.add_to_cart(CLEAN_PRODUCT)

    # Sign a mandate pair that was already stale when it was minted.
    from mandates.schemas import iso_in
    original = session.signer.sign_closed_checkout
    stale_expiry = iso_in(-3600)  # one hour in the past

    closed_checkout, checkout_jwt = original(
        parent_jti=session.open_checkout.jti, cart=session.cart,
        merchant_id="merchant_alpha",
    )
    closed_checkout.expires_at = stale_expiry
    from mandates.crypto import sign
    checkout_jwt = sign(closed_checkout.model_dump(), session.registry.private("agent_key"))

    attestation, attestation_jwt = session.trusted_surface.complete_step_up(
        closed_checkout.checkout_hash, session.cart.total_paise
    )
    from mandates.schemas import ClosedPaymentMandate
    closed_payment = ClosedPaymentMandate(
        parent_jti=closed_checkout.jti, session_id=session.session_id,
        transaction_id=closed_checkout.checkout_hash, amount_paise=session.cart.total_paise,
        payee_id="merchant_alpha", risk_data=attestation.risk,
        risk_attestation_jwt=attestation_jwt, expires_at=stale_expiry,
    )
    payment_jwt = sign(closed_payment.model_dump(), session.registry.private("agent_key"))

    result = session.checkout(
        reuse_closed_checkout_jwt=checkout_jwt, reuse_closed_payment_jwt=payment_jwt,
    )
    succeeded = bool(result.order)
    return AttackResult(
        name="mandate_replay_expired",
        threat_ref="F4 / T-31 (freshness)",
        mode=mode_of(mode),
        succeeded=succeeded,
        evidence=(
            f"mandate expired at {stale_expiry} (one hour before submission) and "
            + (f"was still honoured: order {result.order.order_id} created"
               if succeeded else f"was rejected: {result.outcome.reason}")
        ),
        guard_that_blocked=result.outcome.failed_guard if not succeeded else None,
        order_id=result.order.order_id if result.order else None,
        order_provenance=result.order.provenance if result.order else None,
        agent_kind="scripted (no LLM involved -- protocol-level)",
        detail={"expires_at": stale_expiry, "failed_check": result.outcome.reason},
    )
