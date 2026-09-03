"""G5 -- the independent verifier.

Mitigates: structurally, all four attacks. The component that verifies a
mandate is not the component that signed it.

This class is constructed with PUBLIC KEYS ONLY. It cannot mint a mandate, it
cannot see agent internals, and it re-derives every value it is asked to trust
rather than reading that value out of the token it is checking. The
constructor actively rejects anything that looks like a private key, so the
separation cannot rot silently as the code changes.
"""
from __future__ import annotations

from typing import Optional

import jwt
from pydantic import ValidationError

from guard import GuardLayer
from mandates.crypto import verify
from mandates.schemas import (
    Cart,
    CheckoutConstraints,
    ClosedCheckoutMandate,
    ClosedPaymentMandate,
    OpenCheckoutMandate,
    OpenPaymentMandate,
    PaymentConstraints,
    VerificationOutcome,
)


class PrivateKeyLeak(RuntimeError):
    """Raised if a private key is ever handed to the verifier."""


class IndependentVerifier:
    """Verifies mandates using only public material and the guard's decisions."""

    def __init__(self, public_keys: dict[str, str], guard: GuardLayer) -> None:
        for name, pem in public_keys.items():
            if "PRIVATE KEY" in pem:
                raise PrivateKeyLeak(
                    f"verifier was handed a private key for '{name}' -- "
                    "signer/verifier separation (G5) violated"
                )
        self.public_keys = dict(public_keys)
        self.guard = guard

    # --- helpers ------------------------------------------------------------
    def _verify_as(self, token: str, key_name: str, model):
        """Verify `token` against a named public key and parse it into `model`."""
        claims = verify(token, self.public_keys[key_name])
        return model(**claims)

    # --- the pipeline -------------------------------------------------------
    def authorize(
        self,
        open_checkout_jwt: str,
        open_payment_jwt: str,
        closed_checkout_jwt: str,
        closed_payment_jwt: str,
        cart: Cart,
    ) -> VerificationOutcome:
        """Run the full authorisation pipeline.

        The order matters: cryptographic identity first, then binding, then
        policy. Every check is named so the scorecard can attribute a block to
        a specific guard.
        """
        outcome = VerificationOutcome(authorized=True)

        # 1. The user's own mandates. Signed by the USER key.
        try:
            open_checkout = self._verify_as(open_checkout_jwt, "user_key", OpenCheckoutMandate)
            open_payment = self._verify_as(open_payment_jwt, "user_key", OpenPaymentMandate)
        except (jwt.InvalidTokenError, ValidationError) as exc:
            return outcome.add("open_mandate.signature", False, f"user-signed mandate invalid: {exc}", "G5")
        outcome.add("open_mandate.signature", True, "open mandates verified against the user public key", "G5")

        user_constraints: CheckoutConstraints = open_checkout.constraints
        pay_constraints: PaymentConstraints = open_payment.constraints

        # 2. The agent's mandates. Signed by the AGENT key -- a different key.
        try:
            closed_checkout = self._verify_as(closed_checkout_jwt, "agent_key", ClosedCheckoutMandate)
            closed_payment = self._verify_as(closed_payment_jwt, "agent_key", ClosedPaymentMandate)
        except (jwt.InvalidTokenError, ValidationError) as exc:
            return outcome.add("closed_mandate.signature", False, f"agent-signed mandate invalid: {exc}", "G5")
        outcome.add("closed_mandate.signature", True, "closed mandates verified against the agent public key", "G5")

        # 2b. WHOSE constraints govern this transaction? The guard decides.
        #     Guarded: the user-signed ones. Vulnerable: whatever the agent asserted.
        constraints, g, detail = self.guard.effective_constraints(
            user_constraints, closed_checkout.asserted_constraints
        )
        outcome.add("constraints.source", True, detail, g)

        # 3. Delegation chain: the closed mandates must descend from THESE open ones.
        if closed_checkout.parent_jti != open_checkout.jti:
            return outcome.add("delegation.parent", False,
                               "closed checkout mandate does not descend from this open checkout mandate", "G5")
        if closed_checkout.session_id != cart.session_id:
            return outcome.add("delegation.session", False,
                               "mandate session_id does not match the cart's session", "G5")
        outcome.add("delegation.parent", True, f"chains to open mandate {open_checkout.jti[:8]}...", "G5")

        # 4. Freshness + single use, on BOTH closed mandates.
        for label, mandate in (("checkout", closed_checkout), ("payment", closed_payment)):
            ok, g, detail = self.guard.check_expiry(mandate.expires_at)
            outcome.add(f"{label}.expiry", ok, detail, g)
            if not ok:
                return outcome
            ok, g, detail = self.guard.check_nonce(mandate.nonce, mandate.jti)
            outcome.add(f"{label}.nonce", ok, detail, g)
            if not ok:
                return outcome

        # 5. Re-derive the checkout hash from the cart itself (G5).
        derived_hash, g, detail = self.guard.resolve_checkout_hash(cart, closed_checkout.checkout_hash)
        hash_ok = derived_hash == closed_checkout.checkout_hash or not self.guard.engaged
        outcome.add("checkout_hash.rederived", hash_ok, detail, g)
        if not hash_ok:
            return outcome

        # 6. Payment must be bound to THIS checkout.
        if closed_payment.transaction_id != closed_checkout.checkout_hash:
            return outcome.add("payment.binding", False,
                               "closed payment transaction_id does not equal the checkout_hash", "G5")
        outcome.add("payment.binding", True, "payment is bound to this checkout_hash", "G5")

        # 7. Amount, re-computed from the cart -- not read from the mandate.
        actual_total = cart.total_paise
        if closed_checkout.amount_paise != actual_total and self.guard.engaged:
            return outcome.add("amount.consistency", False,
                               f"mandate claims {closed_checkout.amount_paise} paise but the cart totals "
                               f"{actual_total} paise", "G5")
        outcome.add("amount.consistency", True, f"mandate amount matches the cart total ({actual_total} paise)", "G5")

        # 8. Scope re-check against the user's ORIGINAL constraints (G1).
        verdict, g = self.guard.check_scope(cart, constraints)
        outcome.add("scope.recheck", verdict.within_scope, verdict.detail, g)
        if not verdict.within_scope:
            return outcome

        # 9. Merchant pinning (G4).
        ok, g, detail = self.guard.match_merchant(closed_checkout.merchant_id, constraints.allowed_merchants)
        outcome.add("merchant.pinned", ok, detail, g)
        if not ok:
            return outcome

        # 10. Payee pinning -- same rule, applied to where the money goes.
        ok, g, detail = self.guard.match_merchant(closed_payment.payee_id, pay_constraints.allowed_payees)
        outcome.add("payee.pinned", ok, detail, g)
        if not ok:
            return outcome

        # 11. Payment ceiling. Guarded mode takes the lower of the user's payment
        #     cap and the governing checkout cap; vulnerable mode inherits the
        #     agent-asserted cap resolved in step 2b.
        ceiling, g, ceiling_detail = self.guard.payment_ceiling(
            pay_constraints.max_amount_paise, constraints.max_amount_paise
        )
        if closed_payment.amount_paise > ceiling:
            return outcome.add("payment.ceiling", False,
                               f"{closed_payment.amount_paise} paise exceeds the payment cap "
                               f"{ceiling} paise", "G5")
        outcome.add("payment.ceiling", True, f"{ceiling_detail}; charge is within it", g)

        # 12. Risk / step-up (G3).
        decision, g = self.guard.evaluate_risk(
            closed_payment, self.public_keys, closed_checkout.checkout_hash,
            closed_payment.amount_paise, pay_constraints.step_up_threshold_paise,
        )
        outcome.step_up_required = decision.step_up_required
        outcome.add("risk.attested", decision.accepted, decision.detail, g)
        return outcome
