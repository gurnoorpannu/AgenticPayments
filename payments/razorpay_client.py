"""Razorpay test-mode client.

Two implementations behind one interface:
  * LiveRazorpayClient  -- real API calls against rzp_test_ credentials
  * SimulatedRazorpayClient -- used when no test credentials are configured,
    so the attack demo is reproducible by anyone who clones the repo

Which one is in use is reported in every result and printed in the demo
banner. We never silently pretend a simulated order was a real one.
"""
from __future__ import annotations

import uuid
from dataclasses import dataclass, field
from typing import Any, Optional, Protocol

import razorpay

from config import Settings


@dataclass
class OrderResult:
    order_id: str
    amount_paise: int
    currency: str
    status: str
    receipt: str
    live: bool
    payment_link: Optional[str] = None
    raw: dict[str, Any] = field(default_factory=dict)

    @property
    def provenance(self) -> str:
        return "razorpay-test-mode" if self.live else "simulated"


class PaymentClient(Protocol):
    live: bool

    def create_order(self, amount_paise: int, receipt: str, notes: dict[str, str]) -> OrderResult: ...


class LiveRazorpayClient:
    """Real Razorpay test-mode API. Refuses to construct with non-test keys."""

    live = True

    def __init__(self, settings: Settings) -> None:
        if not settings.razorpay_key_id.startswith("rzp_test_"):
            raise ValueError(
                "refusing to construct a Razorpay client with a non-test key id; "
                "this project is test-mode only"
            )
        self._client = razorpay.Client(auth=(settings.razorpay_key_id, settings.razorpay_key_secret))

    def create_order(self, amount_paise: int, receipt: str, notes: dict[str, str]) -> OrderResult:
        order = self._client.order.create(
            {"amount": amount_paise, "currency": "INR", "receipt": receipt[:40], "notes": notes}
        )
        return OrderResult(
            order_id=order["id"],
            amount_paise=order["amount"],
            currency=order["currency"],
            status=order["status"],
            receipt=order.get("receipt", receipt),
            live=True,
            raw=order,
        )


class SimulatedRazorpayClient:
    """Deterministic stand-in. Every result is labelled live=False."""

    live = False

    def __init__(self, settings: Optional[Settings] = None) -> None:
        self.orders: list[OrderResult] = []

    def create_order(self, amount_paise: int, receipt: str, notes: dict[str, str]) -> OrderResult:
        result = OrderResult(
            order_id=f"order_sim_{uuid.uuid4().hex[:14]}",
            amount_paise=amount_paise,
            currency="INR",
            status="created",
            receipt=receipt,
            live=False,
            raw={"simulated": True, "notes": notes},
        )
        self.orders.append(result)
        return result


def build_payment_client(settings: Settings) -> PaymentClient:
    """Use the real test-mode API when credentials are present, else simulate."""
    if settings.razorpay_live:
        return LiveRazorpayClient(settings)
    return SimulatedRazorpayClient(settings)
