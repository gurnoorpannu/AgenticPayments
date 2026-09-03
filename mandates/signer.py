"""Mandate construction and signing.

Deliberately separated from mandates.verifier: the signer holds PRIVATE keys,
the verifier holds only PUBLIC keys. See guard G5.
"""
from __future__ import annotations

from typing import Optional

from mandates.crypto import KeyRegistry, sha256_hex, sign
from mandates.schemas import (
    Cart,
    CheckoutConstraints,
    ClosedCheckoutMandate,
    ClosedPaymentMandate,
    OpenCheckoutMandate,
    OpenPaymentMandate,
    PaymentConstraints,
    RiskAttestation,
    RiskData,
)


def checkout_hash_of(cart: Cart) -> str:
    """The single definition of checkout_hash: sha256 over the canonical cart.

    Both the signer and the independent verifier call THIS function. The
    verifier never trusts the hash carried inside a mandate (G5).
    """
    return sha256_hex(cart.canonical())


class MandateSigner:
    """Signs mandates on behalf of the user (session setup) and agent (checkout)."""

    def __init__(self, registry: KeyRegistry) -> None:
        self._registry = registry

    # --- user-signed (open) mandates ---------------------------------------
    def sign_open_checkout(self, session_id: str, constraints: CheckoutConstraints) -> tuple[OpenCheckoutMandate, str]:
        mandate = OpenCheckoutMandate(
            session_id=session_id,
            constraints=constraints,
            agent_pk=self._registry.fingerprint("agent_key"),
        )
        return mandate, sign(mandate.model_dump(), self._registry.private("user_key"))

    def sign_open_payment(self, session_id: str, constraints: PaymentConstraints) -> tuple[OpenPaymentMandate, str]:
        mandate = OpenPaymentMandate(
            session_id=session_id,
            constraints=constraints,
            agent_pk=self._registry.fingerprint("agent_key"),
        )
        return mandate, sign(mandate.model_dump(), self._registry.private("user_key"))

    # --- agent-signed (closed) mandates ------------------------------------
    def sign_closed_checkout(
        self,
        parent_jti: str,
        cart: Cart,
        merchant_id: str,
        amount_paise: Optional[int] = None,
        checkout_hash: Optional[str] = None,
        asserted_constraints: Optional[CheckoutConstraints] = None,
    ) -> tuple[ClosedCheckoutMandate, str]:
        """Sign a closed checkout mandate.

        `amount_paise` and `checkout_hash` are overridable ONLY so that attack
        scenarios can construct mandates whose claimed values diverge from the
        real cart. The honest path leaves both as None.
        """
        mandate = ClosedCheckoutMandate(
            parent_jti=parent_jti,
            session_id=cart.session_id,
            asserted_constraints=asserted_constraints,
            checkout_hash=checkout_hash if checkout_hash is not None else checkout_hash_of(cart),
            amount_paise=amount_paise if amount_paise is not None else cart.total_paise,
            merchant_id=merchant_id,
        )
        return mandate, sign(mandate.model_dump(), self._registry.private("agent_key"))

    def sign_closed_payment(
        self,
        parent_jti: str,
        session_id: str,
        transaction_id: str,
        amount_paise: int,
        payee_id: str,
        risk_data: Optional[RiskData] = None,
        risk_attestation_jwt: Optional[str] = None,
    ) -> tuple[ClosedPaymentMandate, str]:
        mandate = ClosedPaymentMandate(
            parent_jti=parent_jti,
            session_id=session_id,
            transaction_id=transaction_id,
            amount_paise=amount_paise,
            payee_id=payee_id,
            risk_data=risk_data,
            risk_attestation_jwt=risk_attestation_jwt,
        )
        return mandate, sign(mandate.model_dump(), self._registry.private("agent_key"))


class TrustedSurface:
    """The step-up / risk authority.

    Holds the trusted_surface private key, which the shopping agent does not
    have. Only this component can mint a risk attestation that guard G3 will
    accept, so a malicious agent cannot manufacture "step_up_completed: true".
    """

    ISSUER = "trusted_surface"

    def __init__(self, registry: KeyRegistry) -> None:
        self._registry = registry

    def assess(self, amount_paise: int, step_up_threshold_paise: int) -> RiskData:
        """Honest risk assessment: anything at or above the threshold is high."""
        if amount_paise >= step_up_threshold_paise:
            return RiskData(risk_score="high", step_up_completed=False, method="none")
        return RiskData(risk_score="low", step_up_completed=False, method="none")

    def complete_step_up(self, transaction_id: str, amount_paise: int) -> tuple[RiskAttestation, str]:
        """Simulate the user actually completing a 3DS2 challenge, then attest to it."""
        risk = RiskData(
            risk_score="low",
            step_up_completed=True,
            method="3ds2",
            transaction_id=transaction_id,
        )
        attestation = RiskAttestation(
            issuer=self.ISSUER, transaction_id=transaction_id, risk=risk
        )
        return attestation, sign(attestation.model_dump(), self._registry.private("trusted_surface_key"))

    def attest_without_step_up(self, transaction_id: str, amount_paise: int, threshold: int) -> tuple[RiskAttestation, str]:
        """Attest to a low-risk transaction that genuinely did not need step-up."""
        risk = self.assess(amount_paise, threshold)
        risk.transaction_id = transaction_id
        attestation = RiskAttestation(
            issuer=self.ISSUER, transaction_id=transaction_id, risk=risk
        )
        return attestation, sign(attestation.model_dump(), self._registry.private("trusted_surface_key"))
