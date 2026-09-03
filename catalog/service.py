"""Catalog service.

The catalog is the canonical *untrusted* data source in this threat model.
Product descriptions are merchant-controlled free text; nothing about them is
signed. Everything this module returns must be treated as attacker-influenced.
"""
from __future__ import annotations

import json
from pathlib import Path
from typing import Any, Optional

from pydantic import BaseModel

from mandates.schemas import CartItem

_CATALOG_PATH = Path(__file__).resolve().parent / "products.json"


class Product(BaseModel):
    product_id: str
    name: str
    price_paise: int
    category: str
    merchant_id: str
    description: str
    poisoned: bool = False
    poison_variant: Optional[str] = None
    lookalike: bool = False

    def to_cart_item(self, quantity: int = 1) -> CartItem:
        return CartItem(
            product_id=self.product_id,
            name=self.name,
            unit_price_paise=self.price_paise,
            quantity=quantity,
            category=self.category,
            merchant_id=self.merchant_id,
        )


class CatalogService:
    def __init__(self, path: Path = _CATALOG_PATH) -> None:
        raw: dict[str, Any] = json.loads(path.read_text())
        self.canonical_merchant: str = raw["canonical_merchant"]
        self.merchants: dict[str, dict] = raw["merchants"]
        self.products: list[Product] = [Product(**p) for p in raw["products"]]

    def all(self) -> list[Product]:
        return list(self.products)

    def get(self, product_id: str) -> Optional[Product]:
        return next((p for p in self.products if p.product_id == product_id), None)

    def search(self, query: str, include_lookalikes: bool = True) -> list[Product]:
        """Substring search over name/description/category.

        Returns raw, unsanitised product records. Wrapping them for LLM
        consumption is the caller's job -- see guard.untrusted_content (G1).
        """
        q = query.lower().strip()
        hits = [
            p
            for p in self.products
            if q in p.name.lower() or q in p.description.lower() or q in p.category.lower()
        ]
        if not include_lookalikes:
            hits = [p for p in hits if not p.lookalike]
        return hits
