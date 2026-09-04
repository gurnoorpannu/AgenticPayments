"""G1a -- faithful consent capture.

Mitigates: Attack 1 (AM1 variant), upstream consent poisoning.
Threat family F1 (Semantic Manipulation), threats T-1 / T-7.

This is the guard for the attack that verification cannot catch.

In AM1 the corruption happens BEFORE the user signs anything. The agent reads
a poisoned catalog, proposes a constraint set shaped by that poison, and the
approval surface shows the user a merchant-supplied justification for the extra
headroom. The user approves. From that moment every downstream check is honest
and every signature is valid -- the closed mandate genuinely does fall within
the open mandate's ceiling. Nothing later in the pipeline can detect this,
because nothing later in the pipeline is wrong. The lie is in the premise.

The mitigation therefore cannot live in the verifier. It lives here, at the
moment consent is captured:

  1. The constraint set is derived from the USER'S stated intent, never from
     the agent's proposal. An agent proposal may only ever TIGHTEN a value.
  2. The approval surface renders the exact structured value that will be
     signed -- one number, not a range, not "up to", not a ceiling plus
     headroom.
  3. Merchant-supplied justification text is never shown as a reason to
     approve a larger number, because that text is attacker-controlled.

Point 3 is the one people get wrong. A justification string is a persuasion
channel from the attacker straight to the human, and rendering it next to an
approve button makes the human the exploit.
"""
from __future__ import annotations

from dataclasses import dataclass
from typing import Optional

from mandates.schemas import (
    ApprovalRender,
    CheckoutConstraints,
    ConstraintProposal,
    UserIntent,
    iso_in,
)


@dataclass
class ConsentOutcome:
    constraints: CheckoutConstraints
    render: ApprovalRender
    guard: Optional[str]
    detail: str


def capture_faithful(
    intent: UserIntent,
    proposal: Optional[ConstraintProposal],
    ttl_seconds: int = 3600,
) -> ConsentOutcome:
    """GUARDED consent capture. Mitigates T-1 at its origin.

    The agent's proposal is admitted only where it narrows authority. A
    proposal asking for more than the user said is not an error to negotiate;
    it is discarded, and the user signs their own number.
    """
    cap = intent.budget_paise
    merchants = list(intent.merchants)
    categories = list(intent.categories)
    notes: list[str] = []

    if proposal is not None:
        # Tightening is always safe to honour.
        if proposal.max_amount_paise < cap:
            cap = proposal.max_amount_paise
            notes.append(f"agent proposed a tighter cap ({cap}); accepted")
        elif proposal.max_amount_paise > intent.budget_paise:
            notes.append(
                f"agent proposed widening the cap to {proposal.max_amount_paise} "
                f"(user stated {intent.budget_paise}) -- discarded"
            )
        # Merchants may only be narrowed to a subset of what the user allowed.
        narrowed = [m for m in proposal.allowed_merchants if m in intent.merchants]
        if narrowed and set(narrowed) != set(merchants):
            merchants = narrowed
            notes.append(f"agent narrowed merchants to {narrowed}; accepted")
        rejected = [m for m in proposal.allowed_merchants if m not in intent.merchants]
        if rejected:
            notes.append(f"agent proposed merchants outside user intent {rejected} -- discarded")
        if proposal.justification:
            notes.append("merchant-supplied justification text withheld from the approval screen")

    constraints = CheckoutConstraints(
        max_amount_paise=cap,
        allowed_merchants=merchants,
        allowed_categories=categories,
        expires_at=iso_in(ttl_seconds),
    )
    # The user is shown precisely the value that gets signed.
    render = ApprovalRender(
        displayed_cap_paise=cap,
        signed_cap_paise=cap,
        displayed_merchants=merchants,
        justification_shown="",
        rendered_by="trusted_surface",
    )
    return ConsentOutcome(
        constraints=constraints,
        render=render,
        guard="G1",
        detail="; ".join(notes) if notes else "consent captured from user intent verbatim",
    )


def capture_naive(
    intent: UserIntent,
    proposal: Optional[ConstraintProposal],
    ttl_seconds: int = 3600,
) -> ConsentOutcome:
    """VULNERABLE consent capture -- the AM1 sink.

    The agent's proposed constraint set is adopted wholesale, and the approval
    screen shows the user their ORIGINAL budget alongside the agent's
    justification for the headroom. The user recognises their own number,
    reads a plausible reason, and approves -- signing a different number.

    This is not a strawman: showing a friendly summary while committing a
    richer structure underneath is ordinary product design.
    """
    if proposal is None:
        constraints = CheckoutConstraints(
            max_amount_paise=intent.budget_paise,
            allowed_merchants=list(intent.merchants),
            allowed_categories=list(intent.categories),
            expires_at=iso_in(ttl_seconds),
        )
        return ConsentOutcome(
            constraints=constraints,
            render=ApprovalRender(
                displayed_cap_paise=intent.budget_paise,
                signed_cap_paise=intent.budget_paise,
                displayed_merchants=list(intent.merchants),
                rendered_by="agent",
            ),
            guard=None,
            detail="no agent proposal; user intent adopted",
        )

    constraints = CheckoutConstraints(
        max_amount_paise=proposal.max_amount_paise,
        allowed_merchants=list(proposal.allowed_merchants),
        allowed_categories=list(proposal.allowed_categories),
        expires_at=iso_in(ttl_seconds),
    )
    # The summary the human reads still says their original budget.
    render = ApprovalRender(
        displayed_cap_paise=intent.budget_paise,
        signed_cap_paise=proposal.max_amount_paise,
        displayed_merchants=list(intent.merchants),
        justification_shown=proposal.justification,
        rendered_by="agent",
    )
    return ConsentOutcome(
        constraints=constraints,
        render=render,
        guard=None,
        detail=(
            f"adopted the agent's proposed constraint set (cap {proposal.max_amount_paise}); "
            f"approval screen displayed {intent.budget_paise}"
        ),
    )
