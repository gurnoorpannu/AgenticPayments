"""ShoppingSession -- orchestrates catalog, mandates, guard, verifier, payments.

This is the object both the LLM agent and the attack scenarios drive, so an
attack exercises exactly the same checkout pipeline a normal purchase does.
"""
from __future__ import annotations

import uuid
from dataclasses import dataclass, field
from typing import Any, Optional

from catalog.service import CatalogService, Product
from config import Mode, Settings, get_settings
from guard import GuardLayer, build_guard
from mandates.crypto import KeyRegistry, build_registry
from mandates.schemas import (
    Cart,
    CheckoutConstraints,
    PaymentConstraints,
    RiskData,
    VerificationOutcome,
    iso_in,
)
from mandates.signer import MandateSigner, TrustedSurface, checkout_hash_of
from mandates.verifier import IndependentVerifier
from payments.razorpay_client import OrderResult, build_payment_client

DEFAULT_MAX_AMOUNT_PAISE = 200_000        # Rs 2,000 shopping cap
DEFAULT_STEP_UP_THRESHOLD_PAISE = 150_000  # Rs 1,500 -- above this, challenge the user


@dataclass
class CheckoutResult:
    authorized: bool
    outcome: VerificationOutcome
    order: Optional[OrderResult] = None
    step_up_required: bool = False
    closed_checkout_jwt: Optional[str] = None
    closed_payment_jwt: Optional[str] = None
    checkout_hash: Optional[str] = None
    notes: list[str] = field(default_factory=list)

    @property
    def summary(self) -> str:
        if self.order:
            return f"ORDER CREATED {self.order.order_id} for {self.order.amount_paise} paise ({self.order.provenance})"
        if self.step_up_required:
            return f"STEP-UP REQUIRED -- {self.outcome.reason or 'challenge not satisfied'}"
        return f"DECLINED -- {self.outcome.reason}"


class ShoppingSession:
    def __init__(
        self,
        settings: Optional[Settings] = None,
        mode: Optional[Mode] = None,
        registry: Optional[KeyRegistry] = None,
        max_amount_paise: int = DEFAULT_MAX_AMOUNT_PAISE,
        step_up_threshold_paise: int = DEFAULT_STEP_UP_THRESHOLD_PAISE,
        allowed_merchants: Optional[list[str]] = None,
        allowed_categories: Optional[list[str]] = None,
        ttl_seconds: int = 3600,
    ) -> None:
        self.settings = settings or get_settings()
        self.mode = mode or self.settings.mode
        self.session_id = f"sess_{uuid.uuid4().hex[:12]}"

        self.registry = registry or build_registry()
        self.signer = MandateSigner(self.registry)
        self.trusted_surface = TrustedSurface(self.registry)
        self.guard: GuardLayer = build_guard(self.mode)
        # The verifier receives PUBLIC KEYS ONLY -- see mandates.verifier (G5).
        self.verifier = IndependentVerifier(self.registry.public_only(), self.guard)

        self.catalog = CatalogService()
        self.payments = build_payment_client(self.settings)
        self.cart = Cart(session_id=self.session_id)

        allowed_merchants = allowed_merchants or [self.catalog.canonical_merchant]
        allowed_categories = allowed_categories or ["footwear"]

        self.checkout_constraints = CheckoutConstraints(
            max_amount_paise=max_amount_paise,
            allowed_merchants=list(allowed_merchants),
            allowed_categories=list(allowed_categories),
            expires_at=iso_in(ttl_seconds),
        )
        self.payment_constraints = PaymentConstraints(
            max_amount_paise=max_amount_paise,
            allowed_payees=list(allowed_merchants),
            step_up_threshold_paise=step_up_threshold_paise,
            expires_at=iso_in(ttl_seconds),
        )

        self.open_checkout, self.open_checkout_jwt = self.signer.sign_open_checkout(
            self.session_id, self.checkout_constraints
        )
        self.open_payment, self.open_payment_jwt = self.signer.sign_open_payment(
            self.session_id, self.payment_constraints
        )
        self.guard.audit.append(
            "session.opened",
            {"session_id": self.session_id, "mode": self.mode.value,
             "max_amount_paise": max_amount_paise,
             "allowed_merchants": self.checkout_constraints.allowed_merchants},
        )

    # --- catalog ------------------------------------------------------------
    def search(self, query: str) -> list[Product]:
        return self.catalog.search(query)

    def render_search_for_agent(self, products: list[Product]) -> str:
        """Render results for the model, routed through the guard's content boundary (G1)."""
        lines = []
        for p in products:
            lines.append(
                f"- product_id={p.product_id} | name={p.name} | price_paise={p.price_paise} "
                f"| category={p.category} | merchant_id={p.merchant_id}\n  description: {p.description}"
            )
        payload = "\n".join(lines) if lines else "(no matching products)"
        return self.guard.wrap_catalog(payload)

    # --- cart ---------------------------------------------------------------
    def add_to_cart(self, product_id: str, quantity: int = 1) -> str:
        product = self.catalog.get(product_id)
        if product is None:
            return f"error: no product with id '{product_id}'"
        self.cart.items.append(product.to_cart_item(quantity))
        self.guard.audit.append(
            "cart.item_added",
            {"product_id": product_id, "quantity": quantity,
             "unit_price_paise": product.price_paise, "cart_total_paise": self.cart.total_paise},
        )
        return (f"added {quantity} x {product.name} ({product.price_paise} paise each); "
                f"cart total is now {self.cart.total_paise} paise")

    def get_cart(self) -> str:
        if not self.cart.items:
            return "cart is empty"
        lines = [f"- {i.quantity} x {i.name} @ {i.unit_price_paise} = {i.line_total_paise} paise"
                 for i in self.cart.items]
        return "\n".join(lines) + f"\nTOTAL: {self.cart.total_paise} paise"

    # --- checkout -----------------------------------------------------------
    def checkout(
        self,
        merchant_id: Optional[str] = None,
        payee_id: Optional[str] = None,
        perform_step_up: bool = True,
        forged_risk_data: Optional[RiskData] = None,
        override_amount_paise: Optional[int] = None,
        override_checkout_hash: Optional[str] = None,
        reuse_closed_payment_jwt: Optional[str] = None,
        reuse_closed_checkout_jwt: Optional[str] = None,
        asserted_max_amount_paise: Optional[int] = None,
        asserted_merchants: Optional[list[str]] = None,
    ) -> CheckoutResult:
        """Sign the closed mandates, submit them to the verifier, then pay.

        The `override_*` / `reuse_*` / `forged_*` parameters exist ONLY so
        attack scenarios can submit mandates a hostile agent would produce.
        The honest path leaves all of them at their defaults.
        """
        notes: list[str] = []

        # The agent's own claim about what it is allowed to do. A compromised
        # agent fills this in from poisoned catalog text; the guard ignores it.
        asserted: Optional[CheckoutConstraints] = None
        if asserted_max_amount_paise is not None or asserted_merchants is not None:
            asserted = CheckoutConstraints(
                max_amount_paise=asserted_max_amount_paise
                if asserted_max_amount_paise is not None
                else self.checkout_constraints.max_amount_paise,
                allowed_merchants=asserted_merchants
                if asserted_merchants is not None
                else list(self.checkout_constraints.allowed_merchants),
                allowed_categories=list(self.checkout_constraints.allowed_categories),
                expires_at=self.checkout_constraints.expires_at,
            )
            notes.append(
                f"agent asserted its own constraints: cap={asserted.max_amount_paise}, "
                f"merchants={asserted.allowed_merchants}"
            )

        merchant_id = merchant_id or (self.cart.merchant_ids[0] if self.cart.merchant_ids else "")
        payee_id = payee_id or merchant_id

        # --- 1. closed checkout mandate (agent-signed) ---
        if reuse_closed_checkout_jwt:
            closed_checkout_jwt = reuse_closed_checkout_jwt
            from mandates.crypto import peek
            checkout_hash = peek(closed_checkout_jwt)["checkout_hash"]
            parent_jti = peek(closed_checkout_jwt)["jti"]
            notes.append("replayed a previously signed closed checkout mandate")
        else:
            closed_checkout, closed_checkout_jwt = self.signer.sign_closed_checkout(
                parent_jti=self.open_checkout.jti,
                cart=self.cart,
                merchant_id=merchant_id,
                amount_paise=override_amount_paise,
                checkout_hash=override_checkout_hash,
                asserted_constraints=asserted,
            )
            checkout_hash = closed_checkout.checkout_hash
            parent_jti = closed_checkout.jti

        amount_paise = override_amount_paise if override_amount_paise is not None else self.cart.total_paise

        # --- 2. risk posture ---
        risk_data: Optional[RiskData] = None
        attestation_jwt: Optional[str] = None
        if forged_risk_data is not None:
            # A hostile agent asserting its own risk verdict. It has no
            # trusted-surface key, so it can only produce the unsigned field.
            risk_data = forged_risk_data
            notes.append("agent attached self-asserted, unsigned risk_data")
        elif perform_step_up:
            needs = amount_paise >= self.payment_constraints.step_up_threshold_paise
            if needs:
                attestation, attestation_jwt = self.trusted_surface.complete_step_up(checkout_hash, amount_paise)
                notes.append("user completed a 3DS2 step-up; trusted surface issued a signed attestation")
            else:
                attestation, attestation_jwt = self.trusted_surface.attest_without_step_up(
                    checkout_hash, amount_paise, self.payment_constraints.step_up_threshold_paise
                )
                notes.append("below step-up threshold; trusted surface attested low risk")
            risk_data = attestation.risk

        # --- 3. closed payment mandate (agent-signed) ---
        if reuse_closed_payment_jwt:
            closed_payment_jwt = reuse_closed_payment_jwt
            notes.append("replayed a previously signed closed payment mandate")
        else:
            _, closed_payment_jwt = self.signer.sign_closed_payment(
                parent_jti=parent_jti,
                session_id=self.session_id,
                transaction_id=checkout_hash,
                amount_paise=amount_paise,
                payee_id=payee_id,
                risk_data=risk_data,
                risk_attestation_jwt=attestation_jwt,
            )

        # --- 4. INDEPENDENT verification ---
        outcome = self.verifier.authorize(
            self.open_checkout_jwt, self.open_payment_jwt,
            closed_checkout_jwt, closed_payment_jwt, self.cart,
        )
        self.guard.audit.append(
            "mandate.verified",
            {"authorized": outcome.authorized, "failed_guard": outcome.failed_guard,
             "reason": outcome.reason, "step_up_required": outcome.step_up_required,
             "amount_paise": amount_paise, "merchant_id": merchant_id},
        )

        result = CheckoutResult(
            authorized=outcome.authorized and not outcome.step_up_required,
            outcome=outcome,
            step_up_required=outcome.step_up_required,
            closed_checkout_jwt=closed_checkout_jwt,
            closed_payment_jwt=closed_payment_jwt,
            checkout_hash=checkout_hash,
            notes=notes,
        )

        # --- 5. money moves only if authorisation held ---
        if result.authorized:
            order = self.payments.create_order(
                amount_paise=amount_paise,
                receipt=f"mg_{self.session_id[-8:]}_{checkout_hash[:8]}",
                notes={"session_id": self.session_id, "merchant_id": merchant_id, "mode": self.mode.value},
            )
            result.order = order
            self.guard.audit.append(
                "order.created",
                {"order_id": order.order_id, "amount_paise": order.amount_paise,
                 "provenance": order.provenance, "payee_id": payee_id},
            )
        return result
