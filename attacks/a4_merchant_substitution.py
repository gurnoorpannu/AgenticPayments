"""Attack 4 -- merchant substitution / typo-squatting.

Threat family F3 (Trust-Root Subversion), threat T-27.

The user allowlisted `merchant_alpha`. The attacker registers
`merchant_a1pha` -- digit one where the letter ell belongs -- and the payment
routes to them. Nothing is forged; the allowlist check simply says yes to the
wrong string.

Every variant below is a real-world identifier confusion class:
  * homoglyph substitution within ASCII (1 for l)
  * Unicode homoglyph (Cyrillic a, U+0430)
  * case variation, which NFKD casefolding erases
  * suffix extension, which substring matching accepts
"""
from __future__ import annotations

from typing import Optional

from agent.session import ShoppingSession
from attacks import AttackResult, mode_of
from config import Mode, Settings, get_settings
from mandates.schemas import UserIntent

CANONICAL = "merchant_alpha"
LOOKALIKE_PRODUCT = "prod_runner_clone"  # sold by merchant_a1pha


def _session(settings: Settings, mode: Mode) -> ShoppingSession:
    intent = UserIntent(goal="buy running shoes", budget_paise=200_000,
                        merchants=[CANONICAL], categories=["footwear"])
    return ShoppingSession(settings=settings, mode=mode, intent=intent)


def _run(mode: Mode, settings: Optional[Settings], payee: str, name: str, note: str,
         use_lookalike_product: bool = True) -> AttackResult:
    settings = settings or get_settings()
    session = _session(settings, mode)
    session.add_to_cart(LOOKALIKE_PRODUCT if use_lookalike_product else "prod_runner")

    result = session.checkout(merchant_id=payee, payee_id=payee)
    # Success means an order was created for a merchant the user never allowed.
    succeeded = bool(result.order) and payee not in session.checkout_constraints.allowed_merchants

    evidence = (
        f"user allowlisted '{CANONICAL}'. Payment was routed to '{payee}' ({note}). "
    )
    evidence += (
        f"The order was created anyway: {result.order.order_id} for "
        f"{result.order.amount_paise} paise -- funds go to the wrong party."
        if succeeded else f"Rejected: {result.outcome.reason}"
    )

    return AttackResult(
        name=name,
        threat_ref="F3 / T-27",
        mode=mode_of(mode),
        succeeded=succeeded,
        evidence=evidence,
        guard_that_blocked=result.outcome.failed_guard if not succeeded else None,
        order_id=result.order.order_id if result.order else None,
        order_provenance=result.order.provenance if result.order else None,
        agent_kind="scripted (no LLM involved -- protocol-level)",
        detail={
            "allowlisted_merchant": CANONICAL,
            "actual_payee": payee,
            "confusion_class": note,
            "codepoints_differ_at": [
                i for i, (a, b) in enumerate(zip(CANONICAL, payee)) if a != b
            ] or ("length differs" if len(CANONICAL) != len(payee) else []),
            "failed_check": result.outcome.reason,
        },
    )


def typosquat_digit_one(mode: Mode, settings: Optional[Settings] = None) -> AttackResult:
    return _run(mode, settings, "merchant_a1pha", "merchant_substitution_typosquat",
                "ASCII homoglyph: digit '1' for letter 'l'")


def homoglyph_cyrillic(mode: Mode, settings: Optional[Settings] = None) -> AttackResult:
    return _run(mode, settings, "merchant_аlpha", "merchant_substitution_unicode_homoglyph",
                "Unicode homoglyph: Cyrillic 'a' U+0430 for Latin 'a'", use_lookalike_product=False)


def case_variation(mode: Mode, settings: Optional[Settings] = None) -> AttackResult:
    return _run(mode, settings, "Merchant_Alpha", "merchant_substitution_case_variation",
                "case variation erased by casefolding", use_lookalike_product=False)


def suffix_extension(mode: Mode, settings: Optional[Settings] = None) -> AttackResult:
    return _run(mode, settings, "merchant_alpha_payouts", "merchant_substitution_suffix",
                "suffix extension accepted by substring matching", use_lookalike_product=False)
