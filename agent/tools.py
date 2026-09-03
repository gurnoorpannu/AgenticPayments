"""The agent's four tools, plus OpenAI-compatible schemas and a dispatcher."""
from __future__ import annotations

import json
from typing import Any

from agent.session import ShoppingSession

TOOL_SCHEMAS: list[dict[str, Any]] = [
    {
        "type": "function",
        "function": {
            "name": "search_catalog",
            "description": "Search the merchant catalog for products matching a query.",
            "parameters": {
                "type": "object",
                "properties": {"query": {"type": "string", "description": "Search terms, e.g. 'running shoe'"}},
                "required": ["query"],
            },
        },
    },
    {
        "type": "function",
        "function": {
            "name": "add_to_cart",
            "description": "Add a product to the cart by its product_id.",
            "parameters": {
                "type": "object",
                "properties": {
                    "product_id": {"type": "string"},
                    "quantity": {"type": "integer", "default": 1},
                },
                "required": ["product_id"],
            },
        },
    },
    {
        "type": "function",
        "function": {
            "name": "get_cart",
            "description": "Show the current cart contents and total.",
            "parameters": {"type": "object", "properties": {}},
        },
    },
    {
        "type": "function",
        "function": {
            "name": "checkout",
            "description": "Finalise the cart, sign the closed mandates and submit for payment.",
            "parameters": {
                "type": "object",
                "properties": {
                    "merchant_id": {"type": "string", "description": "Merchant to route the order to."},
                    "authorized_max_paise": {
                        "type": "integer",
                        "description": "The spending cap you understand applies to this purchase, in paise.",
                    },
                },
            },
        },
    },
]


def dispatch(session: ShoppingSession, name: str, arguments: dict[str, Any]) -> str:
    """Execute one tool call against the session and return a string result."""
    if name == "search_catalog":
        products = session.search(arguments.get("query", ""))
        # Catalog text passes through the guard's untrusted-content boundary (G1).
        return session.render_search_for_agent(products)

    if name == "add_to_cart":
        return session.add_to_cart(arguments["product_id"], int(arguments.get("quantity", 1)))

    if name == "get_cart":
        return session.get_cart()

    if name == "checkout":
        result = session.checkout(
            merchant_id=arguments.get("merchant_id"),
            asserted_max_amount_paise=arguments.get("authorized_max_paise"),
        )
        return json.dumps({
            "authorized": result.authorized,
            "summary": result.summary,
            "failed_guard": result.outcome.failed_guard,
            "reason": result.outcome.reason,
        })

    return f"error: unknown tool '{name}'"
