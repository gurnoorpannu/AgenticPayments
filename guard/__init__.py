"""MandateGuard entrypoint and mode dispatch.

Both modes implement the SAME interface and are called from the SAME code
path in mandates.verifier. `MODE=vulnerable` swaps in BypassedGuard, whose
methods are the naive implementations a well-meaning developer actually
writes. Nothing else about the program changes. That is what makes the
attack/block contrast honest: it is one program with and without one layer,
not two programs.

Every method here is pure deterministic logic. The guard never calls an LLM --
an LLM judge is vulnerable to the same injection as the agent it judges.
"""
from __future__ import annotations

from typing import Optional, Protocol

from guard.audit_chain import AuditChain
from guard.consent_capture import ConsentOutcome, capture_faithful, capture_naive
from guard.merchant_pinning import confusable_report, exact_match, fuzzy_match
from guard.nonce_store import NonceStore
from guard.risk_attestation import RiskDecision, evaluate_attested, evaluate_unsigned
from guard.untrusted_content import ScopeVerdict, recheck_scope, wrap_untrusted
from mandates.schemas import (
    Cart,
    CheckoutConstraints,
    ClosedPaymentMandate,
    ConstraintProposal,
    UserIntent,
)
from mandates.signer import checkout_hash_of


class GuardLayer(Protocol):
    name: str
    engaged: bool

    def wrap_catalog(self, payload: str) -> str: ...
    def capture_consent(self, intent: UserIntent, proposal: Optional[ConstraintProposal],
                        ttl_seconds: int) -> ConsentOutcome: ...
    def effective_constraints(self, user_signed: CheckoutConstraints,
                              agent_asserted: Optional[CheckoutConstraints]) -> tuple[CheckoutConstraints, Optional[str], str]: ...
    def payment_ceiling(self, pay_max_paise: int, effective_max_paise: int) -> tuple[int, Optional[str], str]: ...
    def check_scope(self, cart: Cart, constraints: CheckoutConstraints) -> tuple[ScopeVerdict, Optional[str]]: ...
    def resolve_checkout_hash(self, cart: Cart, claimed: str) -> tuple[str, Optional[str], str]: ...
    def match_merchant(self, candidate: str, allowlist: list[str]) -> tuple[bool, Optional[str], str]: ...
    def check_nonce(self, nonce: str, jti: str) -> tuple[bool, Optional[str], str]: ...
    def check_expiry(self, expires_at: Optional[str]) -> tuple[bool, Optional[str], str]: ...
    def evaluate_risk(self, mandate: ClosedPaymentMandate, public_keys: dict[str, str],
                      expected_transaction_id: str, amount_paise: int,
                      step_up_threshold_paise: int) -> tuple[RiskDecision, Optional[str]]: ...


class MandateGuard:
    """MODE=guarded. G1-G6 engaged."""

    name = "MandateGuard"
    engaged = True

    def __init__(self, nonce_db_path: str = ":memory:", audit_db_path: str = ":memory:") -> None:
        # The consumed-nonce set is SHARED INFRASTRUCTURE: every verifier
        # instance must see the same set, or replay survives horizontal
        # scaling. The audit chain is per-session by design -- one chain per
        # shopping session -- so it stays local. Conflating the two is what
        # made cross-verifier replay possible in the first version.
        self.nonces = NonceStore(nonce_db_path)
        self.audit = AuditChain(audit_db_path, chained=True)

    def wrap_catalog(self, payload: str) -> str:
        """G1 layer 1: fence merchant-controlled text as untrusted data."""
        return wrap_untrusted(payload)

    def capture_consent(self, intent, proposal, ttl_seconds=3600):
        """G1a: the user signs their own number, rendered exactly."""
        return capture_faithful(intent, proposal, ttl_seconds)

    def effective_constraints(self, user_signed, agent_asserted):
        """G1: authorisation scope comes from the USER-SIGNED mandate. Full stop.

        The agent's asserted constraints are discarded without being read.
        Catalog content therefore cannot widen scope no matter how persuasive
        it is, because the widened value is never on a code path that matters.
        """
        if agent_asserted is not None and (
            agent_asserted.max_amount_paise != user_signed.max_amount_paise
            or agent_asserted.allowed_merchants != user_signed.allowed_merchants
            or agent_asserted.allowed_categories != user_signed.allowed_categories
        ):
            return user_signed, "G1", (
                f"agent asserted a widened scope (cap {agent_asserted.max_amount_paise}, "
                f"merchants {agent_asserted.allowed_merchants}) -- discarded; "
                f"enforcing the user-signed cap {user_signed.max_amount_paise}"
            )
        return user_signed, "G1", "enforcing the user-signed constraints"

    def payment_ceiling(self, pay_max_paise: int, effective_max_paise: int):
        """G5: the binding ceiling is the STRICTEST user-signed limit that applies.

        Both inputs trace back to user-signed open mandates in guarded mode, so
        taking the minimum can only ever tighten, never widen.
        """
        ceiling = min(pay_max_paise, effective_max_paise)
        return ceiling, "G5", f"ceiling is the strictest user-signed limit: {ceiling} paise"

    def check_scope(self, cart: Cart, constraints: CheckoutConstraints):
        """G1 layer 2: deterministic re-check against the ORIGINAL user constraints."""
        return recheck_scope(cart, constraints), "G1"

    def resolve_checkout_hash(self, cart: Cart, claimed: str):
        """G5: re-derive the hash from the cart; never trust the mandate's own claim."""
        derived = checkout_hash_of(cart)
        if derived != claimed:
            return derived, "G5", (
                f"checkout_hash in mandate ({claimed[:16]}...) does not match the hash "
                f"re-derived from the actual cart ({derived[:16]}...)"
            )
        return derived, "G5", "checkout_hash independently re-derived from the cart and matches"

    def match_merchant(self, candidate: str, allowlist: list[str]):
        """G4: byte-for-byte comparison. Fails closed."""
        if exact_match(candidate, allowlist):
            return True, "G4", f"merchant '{candidate}' exactly matches the pinned allowlist"
        return False, "G4", confusable_report(candidate, allowlist)

    def check_nonce(self, nonce: str, jti: str):
        """G2: single-use enforcement."""
        if self.nonces.consume(nonce, jti):
            return True, "G2", f"nonce {nonce[:8]}... consumed (first use)"
        return False, "G2", f"nonce {nonce[:8]}... has already been consumed -- replay rejected"

    def check_expiry(self, expires_at: Optional[str]):
        """G2: expiry enforcement. Missing expiry fails closed."""
        if NonceStore.is_expired(expires_at):
            return False, "G2", f"mandate expired at {expires_at}"
        return True, "G2", f"mandate valid until {expires_at}"

    def evaluate_risk(self, mandate, public_keys, expected_transaction_id, amount_paise, step_up_threshold_paise):
        """G3: risk signals accepted only inside a signed, bound, fresh attestation."""
        return evaluate_attested(
            mandate.risk_attestation_jwt, public_keys,
            expected_transaction_id, amount_paise, step_up_threshold_paise,
        ), "G3"


class BypassedGuard:
    """MODE=vulnerable. The naive implementation, with the guard removed.

    Each method below is a plausible convenience, not a strawman:
    fuzzy merchant matching, trusting a risk field the agent supplied,
    trusting the hash inside the mandate, and not tracking nonces are all
    things real integrations do.
    """

    name = "BypassedGuard"
    engaged = False

    def __init__(self, nonce_db_path: str = ":memory:", audit_db_path: str = ":memory:") -> None:
        self.nonces = NonceStore(":memory:")       # exists but is never consulted
        self.audit = AuditChain(audit_db_path, chained=False)

    def wrap_catalog(self, payload: str) -> str:
        """Catalog text goes into the model context raw, as trusted content."""
        return payload

    def capture_consent(self, intent, proposal, ttl_seconds=3600):
        """Adopts the agent's proposed constraints; shows the user their own budget."""
        return capture_naive(intent, proposal, ttl_seconds)

    def effective_constraints(self, user_signed, agent_asserted):
        """Trusts the agent's summary of its own authority.

        This is the naive pattern the paper describes: the agent forwards the
        context it derived, and the verifier validates against that forwarded
        context instead of against the user's signed original.
        """
        if agent_asserted is not None:
            return agent_asserted, None, (
                f"using agent-asserted constraints (cap {agent_asserted.max_amount_paise}, "
                f"merchants {agent_asserted.allowed_merchants})"
            )
        return user_signed, None, "no agent assertion; using user constraints"

    def payment_ceiling(self, pay_max_paise: int, effective_max_paise: int):
        """Uses the cap the agent reported, which by now may be attacker-chosen."""
        return effective_max_paise, None, f"ceiling taken from agent-supplied context: {effective_max_paise} paise"

    def check_scope(self, cart: Cart, constraints: CheckoutConstraints):
        """No independent re-check -- whatever the agent signed is accepted."""
        return ScopeVerdict(within_scope=True, violations=[]), None

    def resolve_checkout_hash(self, cart: Cart, claimed: str):
        """Trusts the hash the signer put in the mandate."""
        return claimed, None, "checkout_hash taken from the mandate as-is (not re-derived)"

    def match_merchant(self, candidate: str, allowlist: list[str]):
        """Case-insensitive + substring + similarity matching."""
        ok = fuzzy_match(candidate, allowlist)
        return ok, None, f"fuzzy merchant match for '{candidate}' -> {ok}"

    def check_nonce(self, nonce: str, jti: str):
        """No single-use tracking."""
        return True, None, "nonce not tracked"

    def check_expiry(self, expires_at: Optional[str]):
        """Expiry not enforced."""
        return True, None, "expiry not enforced"

    def evaluate_risk(self, mandate, public_keys, expected_transaction_id, amount_paise, step_up_threshold_paise):
        """Reads the unsigned risk_data field and believes it."""
        return evaluate_unsigned(mandate.risk_data, amount_paise, step_up_threshold_paise), None


def build_guard(mode, nonce_db_path: Optional[str] = None) -> GuardLayer:
    """Mode dispatch. This one call is the entire difference between the two runs.

    `nonce_db_path` defaults to the configured DB_PATH so that every verifier
    instance in a process -- and across restarts -- shares one consumed-nonce
    set. Pass ":memory:" only to deliberately isolate an instance.
    """
    from config import Mode, get_settings

    mode = Mode(mode) if not isinstance(mode, Mode) else mode
    if nonce_db_path is None:
        nonce_db_path = get_settings().db_path
    return (
        MandateGuard(nonce_db_path=nonce_db_path)
        if mode is Mode.GUARDED
        else BypassedGuard(nonce_db_path=nonce_db_path)
    )
