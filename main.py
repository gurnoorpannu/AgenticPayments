"""FastAPI app: serves the demo page and exposes the attack scenarios as JSON.

Run:  uvicorn main:app --reload    then open http://127.0.0.1:8000
"""
from __future__ import annotations

import json
from pathlib import Path
from typing import Optional

from fastapi import FastAPI, HTTPException, Query
from fastapi.responses import FileResponse, JSONResponse
from fastapi.staticfiles import StaticFiles

from attacks import a1_catalog_injection as a1
from attacks import a2_mandate_replay as a2
from attacks import a3_risk_data_spoof as a3
from attacks import a4_merchant_substitution as a4
from attacks import a5_known_gaps as a5
from config import Mode, get_settings

BASE = Path(__file__).resolve().parent
STATIC = BASE / "static"
RESULTS = BASE / "results"

app = FastAPI(
    title="MandateGuard",
    description="Adversarial testing layer for agentic payments (AP2/UAP-style mandates).",
    version="0.1.0",
)

SCENARIOS = {
    "consent_poisoning": a1.consent_poisoning,
    "consent_poisoning_indirect": a1.consent_poisoning_indirect,
    "claimed_constraints": a1.claimed_constraints,
    "replay_immediate": a2.replay_immediate,
    "replay_delayed": a2.replay_after_delay,
    "replay_expired": a2.replay_expired,
    "cross_verifier_replay": a2.cross_verifier_replay,
    "risk_spoof_step_up": a3.spoof_low_risk,
    "risk_spoof_low_score": a3.spoof_low_score_only,
    "risk_wrong_signer": a3.malformed_risk_schema,
    "merchant_typosquat": a4.typosquat_digit_one,
    "merchant_homoglyph": a4.homoglyph_cyrillic,
    "merchant_case": a4.case_variation,
    "merchant_suffix": a4.suffix_extension,
    "gap_rendered_vs_signed": a5.rendered_vs_signed_divergence,
    "gap_compromised_key": a5.compromised_agent_key,
}


@app.get("/", include_in_schema=False)
def index() -> FileResponse:
    return FileResponse(STATIC / "index.html")


@app.get("/api/config")
def api_config() -> dict:
    """Report exactly what this instance is wired to. No claims we cannot back."""
    settings = get_settings()
    return {
        **settings.describe(),
        "razorpay_live": settings.razorpay_live,
        "llm_live": settings.llm_live,
        "scenarios": sorted(SCENARIOS),
    }


@app.post("/api/attack/{name}")
def api_attack(name: str, mode: str = Query("guarded", pattern="^(vulnerable|guarded)$")) -> dict:
    """Run one scenario in one mode and return the structured result."""
    scenario = SCENARIOS.get(name)
    if scenario is None:
        raise HTTPException(404, f"unknown scenario '{name}'")
    result = scenario(Mode(mode), get_settings())
    return result.to_dict()


@app.post("/api/contrast/{name}")
def api_contrast(name: str) -> dict:
    """Run one scenario in BOTH modes -- the core artifact of this project."""
    scenario = SCENARIOS.get(name)
    if scenario is None:
        raise HTTPException(404, f"unknown scenario '{name}'")
    settings = get_settings()
    vulnerable = scenario(Mode.VULNERABLE, settings).to_dict()
    guarded = scenario(Mode.GUARDED, settings).to_dict()
    return {
        "scenario": name,
        "vulnerable": vulnerable,
        "guarded": guarded,
        "blocked": vulnerable["succeeded"] and not guarded["succeeded"],
        "guard": guarded["guard_that_blocked"],
    }


@app.post("/api/scorecard")
def api_scorecard() -> dict:
    """Regenerate the full scorecard from a live run."""
    from attacks.runner import run_all

    report = run_all(get_settings())
    RESULTS.mkdir(exist_ok=True)
    (RESULTS / "scorecard.json").write_text(json.dumps(report, indent=2))
    return report


@app.get("/api/scorecard")
def api_scorecard_cached() -> JSONResponse:
    """Return the last generated scorecard without re-running anything."""
    path = RESULTS / "scorecard.json"
    if not path.exists():
        raise HTTPException(404, "no scorecard yet -- POST /api/scorecard to generate one")
    return JSONResponse(json.loads(path.read_text()))


@app.get("/api/purchase")
def api_purchase(mode: str = Query("guarded", pattern="^(vulnerable|guarded)$")) -> dict:
    """Run the honest, agent-driven purchase end to end."""
    from agent.session import ShoppingSession
    from agent.shopping_agent import build_agent

    settings = get_settings()
    session = ShoppingSession(settings=settings, mode=Mode(mode))
    agent = build_agent(settings)
    run = agent.run(session)
    intact, chain_detail = session.guard.audit.verify_chain()
    return {
        "agent_kind": run.agent_kind,
        "session_id": session.session_id,
        "steps": [{"tool": s.tool, "arguments": s.arguments, "result": s.result[:400]} for s in run.steps],
        "cart_total_paise": session.cart.total_paise,
        "obeyed_injection": run.obeyed_injection,
        "audit_chain_intact": intact,
        "audit_chain_detail": chain_detail,
    }


if STATIC.exists():
    app.mount("/static", StaticFiles(directory=STATIC), name="static")
