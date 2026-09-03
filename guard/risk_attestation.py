"""G3 -- signed risk attestation.

Mitigates: Attack 3, risk_data spoofing.
Threat family F4 (State-Binding Failures), threat T-34.

The vulnerability is not that risk data is wrong; it is that risk data is
*unattributable*. An unsigned `{"risk_score": "low", "step_up_completed": true}`
blob names no issuer, so the verifier has no basis to believe it -- yet the
naive path reads it directly and skips the challenge.

This guard accepts risk signals only inside an attestation that is:
  1. signed by an authorised issuer (the Trusted Surface key),
  2. schema-valid,
  3. bound to THIS transaction id,
  4. unexpired.
Anything else forces step-up. Fails closed.
"""
from __future__ import annotations

from dataclasses import dataclass
from typing import Optional

import jwt
from pydantic import ValidationError

from mandates.crypto import verify
from mandates.schemas import RiskAttestation, RiskData, parse_iso

#: Issuers whose risk attestations we accept, mapped to the registry key name.
AUTHORISED_ISSUERS: dict[str, str] = {"trusted_surface": "trusted_surface_key"}


@dataclass
class RiskDecision:
    accepted: bool
    step_up_required: bool
    detail: str
    risk: Optional[RiskData] = None


def evaluate_attested(
    attestation_jwt: Optional[str],
    public_keys: dict[str, str],
    expected_transaction_id: str,
    amount_paise: int,
    step_up_threshold_paise: int,
) -> RiskDecision:
    """GUARDED risk evaluation. Mitigates T-34.

    Note the ordering: we decide whether step-up is *needed* from the amount --
    a value the verifier already knows independently -- and only then consult
    the attestation to see whether it was actually performed. The attestation
    can never be used to argue that a challenge was unnecessary.
    """
    needs_step_up = amount_paise >= step_up_threshold_paise

    if attestation_jwt is None:
        if needs_step_up:
            return RiskDecision(False, True, "no risk attestation present; step-up required")
        return RiskDecision(True, False, "no attestation needed below step-up threshold")

    # 1. signature by an authorised issuer
    claims = None
    for issuer, key_name in AUTHORISED_ISSUERS.items():
        pub = public_keys.get(key_name)
        if not pub:
            continue
        try:
            claims = verify(attestation_jwt, pub)
            break
        except jwt.InvalidTokenError:
            continue
    if claims is None:
        return RiskDecision(
            False, True,
            "risk attestation is not signed by any authorised issuer -- rejected, step-up forced",
        )

    # 2. schema validity
    try:
        attestation = RiskAttestation(**claims)
    except ValidationError as exc:
        return RiskDecision(
            False, True,
            f"risk attestation failed schema validation ({exc.error_count()} errors) -- step-up forced",
        )

    if attestation.issuer not in AUTHORISED_ISSUERS:
        return RiskDecision(False, True, f"issuer '{attestation.issuer}' is not authorised -- step-up forced")

    # 3. binding to this transaction
    if attestation.transaction_id != expected_transaction_id:
        return RiskDecision(
            False, True,
            f"attestation is bound to transaction {attestation.transaction_id[:12]}... "
            f"but this transaction is {expected_transaction_id[:12]}... -- step-up forced",
        )

    # 4. freshness
    from datetime import datetime, timezone
    if parse_iso(attestation.expires_at) <= datetime.now(timezone.utc):
        return RiskDecision(False, True, "risk attestation has expired -- step-up forced")

    # 5. finally: was the challenge actually completed when one was required?
    if needs_step_up and not attestation.risk.step_up_completed:
        return RiskDecision(
            False, True,
            f"amount {amount_paise} >= step-up threshold {step_up_threshold_paise} "
            f"and attestation reports step_up_completed=false -- step-up required",
        )

    return RiskDecision(
        True, False,
        f"attested by '{attestation.issuer}': risk={attestation.risk.risk_score}, "
        f"step_up_completed={attestation.risk.step_up_completed}, method={attestation.risk.method}",
        attestation.risk,
    )


def evaluate_unsigned(
    risk_data: Optional[RiskData],
    amount_paise: int,
    step_up_threshold_paise: int,
) -> RiskDecision:
    """VULNERABLE risk evaluation -- reads the unsigned field and believes it.

    This is the T-34 sink. Present so the attack has a real target.
    """
    if risk_data is None:
        needs = amount_paise >= step_up_threshold_paise
        return RiskDecision(not needs, needs, "no risk_data supplied")
    if risk_data.step_up_completed or risk_data.risk_score == "low":
        return RiskDecision(
            True, False,
            f"trusted unsigned risk_data: risk_score={risk_data.risk_score}, "
            f"step_up_completed={risk_data.step_up_completed}",
            risk_data,
        )
    needs = amount_paise >= step_up_threshold_paise
    return RiskDecision(not needs, needs, f"unsigned risk_data reports {risk_data.risk_score}", risk_data)
