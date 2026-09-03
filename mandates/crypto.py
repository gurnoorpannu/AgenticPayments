"""ES256 (P-256) key management, canonicalisation and JWT sign/verify.

Three genuinely separate keypairs are generated: user, agent and merchant.
Separation is what makes signer/verifier separation (guard G5) meaningful --
the verifier is handed only public keys and therefore *cannot* mint a mandate
even if it wanted to.
"""
from __future__ import annotations

import hashlib
import json
from dataclasses import dataclass, field
from typing import Any

import jwt
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ec

ALGORITHM = "ES256"


# --- canonicalisation -------------------------------------------------------
def canonical_json(obj: Any) -> str:
    """Deterministic JSON encoding used for every hash we compute.

    Sorted keys + no insignificant whitespace, so the same logical cart always
    hashes identically regardless of dict insertion order.
    """
    return json.dumps(obj, sort_keys=True, separators=(",", ":"), ensure_ascii=False)


def sha256_hex(obj: Any) -> str:
    """SHA-256 of the canonical JSON encoding of `obj`."""
    return hashlib.sha256(canonical_json(obj).encode("utf-8")).hexdigest()


# --- keys -------------------------------------------------------------------
@dataclass(frozen=True)
class KeyPair:
    name: str
    private_pem: str
    public_pem: str

    @property
    def fingerprint(self) -> str:
        """Stable short identifier for the public key."""
        return hashlib.sha256(self.public_pem.encode()).hexdigest()[:16]


def generate_keypair(name: str) -> KeyPair:
    """Generate a fresh ES256 / NIST P-256 keypair."""
    key = ec.generate_private_key(ec.SECP256R1())
    private_pem = key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption(),
    ).decode()
    public_pem = (
        key.public_key()
        .public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo,
        )
        .decode()
    )
    return KeyPair(name=name, private_pem=private_pem, public_pem=public_pem)


@dataclass
class KeyRegistry:
    """In-memory public-key registry.

    Stands in for what a real deployment would resolve from a UAP/AP2 issuer
    directory. Simulated -- see README "What we did NOT solve".
    """

    keypairs: dict[str, KeyPair] = field(default_factory=dict)

    def add(self, kp: KeyPair) -> KeyPair:
        self.keypairs[kp.name] = kp
        return kp

    def private(self, name: str) -> str:
        return self.keypairs[name].private_pem

    def public(self, name: str) -> str:
        return self.keypairs[name].public_pem

    def fingerprint(self, name: str) -> str:
        return self.keypairs[name].fingerprint

    def public_only(self) -> dict[str, str]:
        """Export just the public halves -- this is all the verifier ever gets."""
        return {name: kp.public_pem for name, kp in self.keypairs.items()}


def build_registry() -> KeyRegistry:
    """Create the three-key world: user, agent, merchant."""
    reg = KeyRegistry()
    for name in ("user_key", "agent_key", "merchant_key"):
        reg.add(generate_keypair(name))
    return reg


# --- JWT --------------------------------------------------------------------
def sign(payload: dict[str, Any], private_pem: str) -> str:
    """Sign a mandate payload as an ES256 JWT."""
    return jwt.encode(payload, private_pem, algorithm=ALGORITHM)


def verify(token: str, public_pem: str) -> dict[str, Any]:
    """Verify an ES256 JWT and return its claims.

    Raises jwt.InvalidTokenError (or a subclass) on any failure. `algorithms`
    is pinned to ES256 to defeat alg-confusion / alg=none downgrades.

    Note: `exp` is deliberately NOT auto-verified here -- mandate expiry is
    enforced explicitly by the verifier so that an expiry failure is reported
    as a distinct, named check rather than a generic signature error.
    """
    return jwt.decode(
        token,
        public_pem,
        algorithms=[ALGORITHM],
        options={"verify_exp": False, "verify_aud": False},
    )


def peek(token: str) -> dict[str, Any]:
    """Read claims WITHOUT verifying the signature.

    Used only by the vulnerable path and by attack tooling that needs to
    inspect a captured token. Never call this from the guard.
    """
    return jwt.decode(token, options={"verify_signature": False})
