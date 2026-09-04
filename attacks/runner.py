"""Attack runner -- executes every scenario in both modes and emits the scorecard.

Every number this produces comes from an actual run against the actual
pipeline. Nothing is hand-written. Successful attacks in vulnerable mode
create real Razorpay test-mode orders, and the order ids are printed so the
claims can be checked against the Razorpay dashboard.
"""
from __future__ import annotations

import argparse
import json
import platform
import sys
from datetime import datetime, timezone
from pathlib import Path
from typing import Callable, Optional

from attacks import AttackResult
from attacks import a1_catalog_injection as a1
from attacks import a2_mandate_replay as a2
from attacks import a3_risk_data_spoof as a3
from attacks import a4_merchant_substitution as a4
from attacks import a5_known_gaps as a5
from config import Mode, Settings, get_settings

RESULTS_DIR = Path(__file__).resolve().parent.parent / "results"

#: (scenario callable, guard expected to block it). The expected guard is
#: recorded so the scorecard can flag when a DIFFERENT guard caught something --
#: which is information, not an error.
SCENARIOS: list[tuple[Callable[..., AttackResult], Optional[str]]] = [
    (a1.consent_poisoning, "G1"),
    (a1.consent_poisoning_indirect, "G1"),
    (a1.claimed_constraints, "G1"),
    (a2.replay_immediate, "G2"),
    (a2.replay_after_delay, "G2"),
    (a2.replay_expired, "G2"),
    (a3.spoof_low_risk, "G3"),
    (a3.spoof_low_score_only, "G3"),
    (a3.malformed_risk_schema, "G3"),
    (a4.typosquat_digit_one, "G4"),
    (a4.homoglyph_cyrillic, "G4"),
    (a4.case_variation, "G4"),
    (a4.suffix_extension, "G4"),
    # Declared gaps: no guard claims these. They are expected to get through,
    # and they are in the scorecard so the denominator is honest.
    (a2.cross_verifier_replay, "G2"),
    (a5.rendered_vs_signed_divergence, None),
    (a5.compromised_agent_key, None),
]


def run_all(settings: Optional[Settings] = None) -> dict:
    settings = settings or get_settings()
    # Start from a clean consumed-nonce set so a rerun reproduces the same
    # results. In production this store is durable and never reset.
    from guard.nonce_store import NonceStore
    NonceStore(settings.db_path).reset()
    rows: list[dict] = []

    for scenario, expected_guard in SCENARIOS:
        vulnerable = scenario(Mode.VULNERABLE, settings)
        guarded = scenario(Mode.GUARDED, settings)
        rows.append({
            "scenario": vulnerable.name,
            "threat_ref": vulnerable.threat_ref,
            "expected_guard": expected_guard,
            "vulnerable": vulnerable.to_dict(),
            "guarded": guarded.to_dict(),
            "blocked": (not guarded.succeeded) and vulnerable.succeeded,
            "actual_guard": guarded.guard_that_blocked,
            "guard_matched_expectation": guarded.guard_that_blocked == expected_guard,
            "known_gap": expected_guard is None,
            "exploitable_in_vulnerable_mode": vulnerable.succeeded,
        })

    exploitable = [r for r in rows if r["exploitable_in_vulnerable_mode"]]
    blocked = [r for r in exploitable if r["blocked"]]
    missed = [r for r in exploitable if not r["blocked"]]
    claimed = [r for r in rows if not r["known_gap"]]
    claimed_blocked = [r for r in claimed if r["blocked"]]
    not_reproduced = [r for r in rows if not r["exploitable_in_vulnerable_mode"]]

    return {
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "environment": {
            "python": platform.python_version(),
            "razorpay": "live-test-mode" if settings.razorpay_live else "simulated",
            "llm": f"live:{settings.llm_model}" if settings.llm_live else "deterministic-stub",
            "note": (
                "Attacks 2-4 are protocol-level and involve no LLM at all. Attack 1's "
                "agent behaviour uses the deterministic stub, which is written to be "
                "maximally injectable -- it assumes the model is already fully "
                "compromised, which is strictly harder for the guard than a real model "
                "that might resist the injection on its own."
            ),
        },
        "totals": {
            "scenarios": len(rows),
            "claimed_coverage": len(claimed),
            "claimed_blocked": len(claimed_blocked),
            "declared_gaps": len(rows) - len(claimed),
            "exploitable_in_vulnerable_mode": len(exploitable),
            "blocked_in_guarded_mode": len(blocked),
            "missed_in_guarded_mode": len(missed),
            "not_reproduced": len(not_reproduced),
        },
        "misses": [r["scenario"] for r in missed],
        "results": rows,
    }


def print_table(report: dict) -> None:
    w = 44
    print()
    print("=" * 96)
    print("MANDATEGUARD SCORECARD".center(96))
    print("=" * 96)
    env = report["environment"]
    print(f"  python {env['python']}  |  razorpay: {env['razorpay']}  |  llm: {env['llm']}")
    print("-" * 96)
    print(f"{'SCENARIO':<{w}} {'VULNERABLE':<12} {'GUARDED':<10} {'GUARD':<7} {'THREAT'}")
    print("-" * 96)
    for row in report["results"]:
        vuln = "EXPLOITED" if row["exploitable_in_vulnerable_mode"] else "not-repro"
        if not row["exploitable_in_vulnerable_mode"]:
            guarded_label = "n/a"
        else:
            guarded_label = "BLOCKED" if row["blocked"] else "MISSED"
        guard = row["actual_guard"] or "-"
        if row["known_gap"]:
            guarded_label = "MISSED" if row["exploitable_in_vulnerable_mode"] else guarded_label
            flag = " (declared gap)"
        else:
            flag = "" if row["guard_matched_expectation"] or not row["blocked"] else f" (exp {row['expected_guard']})"
        threat = row["threat_ref"].split(" (")[0]
        print(f"{row['scenario']:<{w}} {vuln:<12} {guarded_label:<10} {guard:<7}{flag:<12} {threat}")
    print("-" * 96)
    t = report["totals"]
    print(f"  EXPLOITABLE IN VULNERABLE MODE: {t['exploitable_in_vulnerable_mode']}/{t['scenarios']}")
    print(f"  BLOCKED: {t['blocked_in_guarded_mode']}/{t['exploitable_in_vulnerable_mode']}   "
          f"MISSED: {t['missed_in_guarded_mode']}/{t['exploitable_in_vulnerable_mode']}")
    print(f"  Of the {t['claimed_coverage']} scenarios a guard actually claims: "
          f"{t['claimed_blocked']} blocked. The other {t['declared_gaps']} are declared gaps "
          f"with no guard behind them.")
    if report["misses"]:
        print(f"  MISSES: {', '.join(report['misses'])}")
    else:
        print("  MISSES: none in this scenario set (see README for what is NOT covered)")
    print("=" * 96)
    print()


def print_evidence(report: dict, mode: str) -> None:
    print("=" * 96)
    print(f"EVIDENCE LOG -- MODE={mode}".center(96))
    print("=" * 96)
    for row in report["results"]:
        entry = row[mode]
        status = "EXPLOITED" if entry["succeeded"] else "blocked"
        print(f"\n[{status}] {entry['name']}   ({entry['threat_ref']})")
        print(f"  {entry['evidence']}")
        if entry["order_id"]:
            print(f"  order: {entry['order_id']}  ({entry['order_provenance']})")
        if entry["guard_that_blocked"]:
            print(f"  blocked by: {entry['guard_that_blocked']}")
    print("\n" + "=" * 96 + "\n")


def main() -> int:
    parser = argparse.ArgumentParser(description="Run MandateGuard attack scenarios.")
    parser.add_argument("--evidence", choices=["vulnerable", "guarded", "both"],
                        help="print the full evidence log for a mode")
    parser.add_argument("--json-only", action="store_true", help="emit JSON only")
    args = parser.parse_args()

    settings = get_settings()
    report = run_all(settings)

    RESULTS_DIR.mkdir(exist_ok=True)
    out = RESULTS_DIR / "scorecard.json"
    out.write_text(json.dumps(report, indent=2))

    if args.json_only:
        print(json.dumps(report, indent=2))
        return 0

    print_table(report)
    if args.evidence in ("vulnerable", "both"):
        print_evidence(report, "vulnerable")
    if args.evidence in ("guarded", "both"):
        print_evidence(report, "guarded")
    print(f"scorecard written to {out}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
