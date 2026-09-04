"""MandateGuard demo -- the same attack, run twice.

    python demo.py              # side-by-side contrast for one attack
    python demo.py --all        # full scorecard across every scenario
    python demo.py --purchase   # the honest agent-driven purchase (no attack)
"""
from __future__ import annotations

import argparse
import sys

from rich.console import Console
from rich.panel import Panel
from rich.table import Table
from rich.text import Text

from attacks import a1_catalog_injection as a1
from config import Mode, get_settings

console = Console()

ATTACKS = {
    "consent": (a1.consent_poisoning, "Catalog injection via consent-capture poisoning (AM1)"),
    "claimed": (a1.claimed_constraints, "Catalog injection via claimed constraints (SR3)"),
}


def banner(settings) -> None:
    env = settings.describe()
    rail = "razorpay TEST MODE (real API calls)" if settings.razorpay_live else "SIMULATED payment rail"
    llm = f"LLM: {settings.llm_model}" if settings.llm_live else "LLM: deterministic stub"
    console.print(Panel(
        Text.from_markup(
            "[bold]MandateGuard[/bold] -- adversarial testing layer for agentic payments\n"
            f"[dim]{rail}  |  {llm}[/dim]\n\n"
            "A valid signature proves someone signed something.\n"
            "It does not prove the content reflects what the user wanted."
        ),
        border_style="cyan", padding=(1, 2),
    ))


def show_contrast(key: str, settings) -> None:
    scenario, title = ATTACKS[key]
    console.print(f"\n[bold]ATTACK:[/bold] {title}\n")

    results = {}
    for mode in (Mode.VULNERABLE, Mode.GUARDED):
        with console.status(f"running in {mode.value} mode..."):
            results[mode] = scenario(mode, settings)

    for mode in (Mode.VULNERABLE, Mode.GUARDED):
        r = results[mode]
        if r.succeeded:
            style, verdict = "red", "EXPLOITED"
        else:
            style, verdict = "green", f"BLOCKED by {r.guard_that_blocked}"

        body = Text()
        d = r.detail
        if "user_stated_budget_paise" in d:
            body.append(f"  user stated budget       {d['user_stated_budget_paise']:>8,} paise\n")
            body.append(f"  approval screen showed   {d['displayed_cap_paise']:>8,} paise\n")
            signed_style = "bold red" if not d["consent_faithful"] else "bold green"
            body.append(f"  mandate actually signed  {d['signed_cap_paise']:>8,} paise\n", style=signed_style)
            body.append(f"  cart charged             {d['cart_total_paise']:>8,} paise\n")
            if d.get("justification_forwarded_to_user"):
                body.append(f'\n  merchant text shown to the human:\n    "{d["justification_forwarded_to_user"]}"\n',
                            style="yellow")
        body.append(f"\n  {r.evidence}\n", style="dim")
        if r.order_id:
            body.append(f"\n  order: {r.order_id}  ({r.order_provenance})\n", style="dim")

        console.print(Panel(body, title=f"MODE={mode.value}  ->  {verdict}",
                            border_style=style, padding=(1, 2)))

    v, g = results[Mode.VULNERABLE], results[Mode.GUARDED]
    if v.succeeded and not g.succeeded:
        console.print(Panel(
            Text.from_markup(
                f"[bold green]Same code. Same agent. Same poisoned catalog.[/bold green]\n"
                f"The only difference is one config flag: MODE.\n\n"
                f"Blocked by [bold]{g.guard_that_blocked}[/bold]."),
            border_style="green", padding=(1, 2)))


def show_scorecard(settings) -> None:
    from attacks.runner import run_all
    with console.status("running every scenario in both modes..."):
        report = run_all(settings)

    table = Table(title="MandateGuard scorecard", header_style="bold")
    table.add_column("Scenario", no_wrap=False)
    table.add_column("Vulnerable")
    table.add_column("Guarded")
    table.add_column("Guard")
    table.add_column("Threat")

    for row in report["results"]:
        exploited = row["exploitable_in_vulnerable_mode"]
        vuln = Text("EXPLOITED", style="red") if exploited else Text("not-repro", style="dim")
        if row["blocked"]:
            guarded = Text("BLOCKED", style="green")
        elif row["known_gap"]:
            guarded = Text("MISSED", style="yellow")
        else:
            guarded = Text("MISSED", style="bold red")
        guard = row["actual_guard"] or ("declared gap" if row["known_gap"] else "-")
        table.add_row(row["scenario"], vuln, guarded, guard, row["threat_ref"].split(" (")[0])

    console.print()
    console.print(table)
    t = report["totals"]
    console.print(
        f"\n  [bold]BLOCKED {t['blocked_in_guarded_mode']}/{t['exploitable_in_vulnerable_mode']}[/bold]   "
        f"MISSED {t['missed_in_guarded_mode']}/{t['exploitable_in_vulnerable_mode']}")
    console.print(f"  [dim]{t['claimed_blocked']}/{t['claimed_coverage']} of scenarios a guard claims; "
                  f"{t['declared_gaps']} declared gaps with no guard behind them.[/dim]")
    if report["misses"]:
        console.print(f"  [yellow]Misses: {', '.join(report['misses'])}[/yellow]")
    console.print("\n  [dim]results/scorecard.json regenerated from this run.[/dim]\n")


def show_purchase(settings) -> None:
    from agent.session import ShoppingSession
    from agent.shopping_agent import build_agent

    agent = build_agent(settings)
    session = ShoppingSession(settings=settings, mode=Mode.GUARDED)
    console.print(f"\n[bold]Agent-driven purchase[/bold]  agent={agent.agent_kind}"
                  f"  mode=guarded  session={session.session_id}\n")
    with console.status("agent is shopping..."):
        run = agent.run(session)

    for step in run.steps:
        console.print(f"  [cyan]{step.tool}[/cyan]({step.arguments}) ")
        console.print(f"    [dim]{step.result.strip().splitlines()[0][:110]}[/dim]")

    console.print()
    if run.obeyed_injection:
        console.print(Panel(
            Text.from_markup(
                "[yellow]This agent followed instructions embedded in the catalog[/yellow] and put an\n"
                "out-of-scope item in the cart. That is by design: with no LLM configured the\n"
                "deterministic stub is written to be maximally injectable, so it stands in for a\n"
                "fully compromised model. The guard declined the checkout anyway -- which is the\n"
                "property worth demonstrating.\n\n"
                "[dim]Configure LLM_API_KEY to run this with a real model, which may resist the\n"
                "injection on its own and complete the purchase normally.[/dim]"),
            border_style="yellow", padding=(1, 2)))
    else:
        console.print(Panel(
            Text.from_markup(
                "[green]The agent ignored the poisoned listings[/green] and bought the item the user\n"
                "asked for, within the approved ceiling."),
            border_style="green", padding=(1, 2)))

    intact, chain_detail = session.guard.audit.verify_chain()
    console.print(f"\n  cart total:  {session.cart.total_paise:,} paise")
    console.print(f"  user cap:    {session.checkout_constraints.max_amount_paise:,} paise")
    console.print(f"  audit chain: [{'green' if intact else 'red'}]{chain_detail}[/]\n")


def main() -> int:
    parser = argparse.ArgumentParser(description="MandateGuard demo")
    parser.add_argument("--attack", choices=sorted(ATTACKS), default="consent")
    parser.add_argument("--all", action="store_true", help="run the full scorecard")
    parser.add_argument("--purchase", action="store_true", help="show the honest purchase flow")
    args = parser.parse_args()

    settings = get_settings()
    banner(settings)
    if args.purchase:
        show_purchase(settings)
    elif args.all:
        show_scorecard(settings)
    else:
        show_contrast(args.attack, settings)
    return 0


if __name__ == "__main__":
    sys.exit(main())
