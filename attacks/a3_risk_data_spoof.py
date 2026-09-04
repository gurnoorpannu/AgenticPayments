"""Attack 3 -- risk_data spoofing.

Threat family F4 (State-Binding Failures), threat T-34.

A transaction above the step-up threshold should trigger a challenge. The
agent instead attaches its own risk verdict -- `risk_score: "low"`,
`step_up_completed: true`, `method: "3ds2"` -- to a transaction that never
underwent any verification at all.

The field is unsigned, so it names no issuer. The naive verifier reads it and
skips the challenge. The agent has just graded its own exam.
"""
from __future__ import annotations

from typing import Optional

from agent.session import ShoppingSession
from attacks import AttackResult, mode_of
from config import Mode, Settings, get_settings
from mandates.schemas import RiskData, UserIntent

EXPENSIVE_PRODUCT = "prod_runner"  # 179900 paise, above the 150000 step-up threshold


def _session(settings: Settings, mode: Mode) -> ShoppingSession:
    intent = UserIntent(goal="buy running shoes", budget_paise=200_000,
                        merchants=["merchant_alpha"], categories=["footwear"])
    return ShoppingSession(settings=settings, mode=mode, intent=intent)


def _run(mode: Mode, settings: Optional[Settings], forged: RiskData, name: str, note: str) -> AttackResult:
    settings = settings or get_settings()
    session = _session(settings, mode)
    session.add_to_cart(EXPENSIVE_PRODUCT)
    threshold = session.payment_constraints.step_up_threshold_paise
    amount = session.cart.total_paise

    result = session.checkout(perform_step_up=False, forged_risk_data=forged)
    # Success means money moved on a transaction that should have been challenged.
    succeeded = bool(result.order) and amount >= threshold and not result.step_up_required

    evidence = (
        f"transaction of {amount} paise is at or above the {threshold} paise step-up "
        f"threshold. No challenge was performed. The agent attached {note} "
    )
    evidence += (
        f"and the payment completed without step-up: order {result.order.order_id}."
        if succeeded else f"and was stopped: {result.outcome.reason}"
    )

    return AttackResult(
        name=name,
        threat_ref="F4 / T-34",
        mode=mode_of(mode),
        succeeded=succeeded,
        evidence=evidence,
        guard_that_blocked=result.outcome.failed_guard if not succeeded else None,
        order_id=result.order.order_id if result.order else None,
        order_provenance=result.order.provenance if result.order else None,
        agent_kind="scripted (no LLM involved -- protocol-level)",
        detail={
            "amount_paise": amount,
            "step_up_threshold_paise": threshold,
            "step_up_actually_performed": False,
            "step_up_required_by_verifier": result.step_up_required,
            "forged_risk_data": forged.model_dump(),
            "failed_check": result.outcome.reason,
        },
    )


def spoof_low_risk(mode: Mode, settings: Optional[Settings] = None) -> AttackResult:
    """The straightforward forgery: claim the challenge was completed."""
    return _run(
        mode, settings,
        RiskData(risk_score="low", step_up_completed=True, method="3ds2"),
        "risk_data_spoof_step_up_claimed",
        'an unsigned risk_data claiming {risk_score: low, step_up_completed: true, method: 3ds2}',
    )


def spoof_low_score_only(mode: Mode, settings: Optional[Settings] = None) -> AttackResult:
    """Weaker forgery: claim low risk without claiming a completed challenge."""
    return _run(
        mode, settings,
        RiskData(risk_score="low", step_up_completed=False, method="none"),
        "risk_data_spoof_low_score_only",
        'an unsigned risk_data claiming {risk_score: low, step_up_completed: false}',
    )


def malformed_risk_schema(mode: Mode, settings: Optional[Settings] = None) -> AttackResult:
    """Off-schema risk payload smuggled in as a signed-looking attestation.

    The agent cannot sign a trusted-surface attestation, so it supplies a
    syntactically valid JWT signed with its OWN key. A verifier that parses
    the token without checking WHICH key signed it will accept it.
    """
    settings = settings or get_settings()
    session = _session(settings, mode)
    session.add_to_cart(EXPENSIVE_PRODUCT)
    threshold = session.payment_constraints.step_up_threshold_paise
    amount = session.cart.total_paise

    from mandates.crypto import sign
    from mandates.schemas import RiskAttestation
    # Self-issued: correct shape, wrong signer.
    forged_attestation = RiskAttestation(
        issuer="trusted_surface",
        transaction_id="0" * 64,
        risk=RiskData(risk_score="low", step_up_completed=True, method="3ds2"),
    )
    forged_jwt = sign(forged_attestation.model_dump(), session.registry.private("agent_key"))

    cart_hash = None
    from mandates.signer import checkout_hash_of
    cart_hash = checkout_hash_of(session.cart)
    closed_checkout, checkout_jwt = session.signer.sign_closed_checkout(
        parent_jti=session.open_checkout.jti, cart=session.cart, merchant_id="merchant_alpha")
    _, payment_jwt = session.signer.sign_closed_payment(
        parent_jti=closed_checkout.jti, session_id=session.session_id,
        transaction_id=closed_checkout.checkout_hash, amount_paise=amount,
        payee_id="merchant_alpha",
        risk_data=RiskData(risk_score="low", step_up_completed=True, method="3ds2"),
        risk_attestation_jwt=forged_jwt,
    )
    outcome = session.verifier.authorize(
        session.open_checkout_jwt, session.open_payment_jwt, checkout_jwt, payment_jwt, session.cart)

    order = None
    if outcome.authorized and not outcome.step_up_required:
        order = session.payments.create_order(
            amount, f"mg_a3m_{closed_checkout.checkout_hash[:8]}", {"scenario": "malformed_risk"})
    succeeded = bool(order)

    return AttackResult(
        name="risk_attestation_wrong_signer",
        threat_ref="F4 / T-34 (attestation forgery)",
        mode=mode_of(mode),
        succeeded=succeeded,
        evidence=(
            "agent self-issued a risk attestation claiming issuer 'trusted_surface' but signed "
            "it with the AGENT key, and bound it to a bogus transaction id. "
            + (f"It was accepted: order {order.order_id} created without step-up."
               if succeeded else f"Rejected: {outcome.reason}")
        ),
        guard_that_blocked=outcome.failed_guard if not succeeded else None,
        order_id=order.order_id if order else None,
        order_provenance=order.provenance if order else None,
        agent_kind="scripted (no LLM involved -- protocol-level)",
        detail={
            "amount_paise": amount,
            "step_up_threshold_paise": threshold,
            "claimed_issuer": "trusted_surface",
            "actual_signing_key": "agent_key",
            "attestation_transaction_id": "0" * 64,
            "real_checkout_hash": cart_hash,
            "step_up_required_by_verifier": outcome.step_up_required,
            "failed_check": outcome.reason,
        },
    )
