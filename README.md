# MandateGuard

An adversarial testing layer for agentic payments. Agentic checkout demos generally
show the happy path. This one shows what happens when the counterparty is hostile,
and implements the middleware that stops it.

Built against Razorpay test-mode APIs. Threat taxonomy from
[*Beyond the Mandate: A Systematic Security Analysis of the Agent Payments Protocol
(AP2)*](https://arxiv.org/abs/2608.23858) (Aviv, Gandhi, Bitton & Shabtai).

![MandateGuard](docs/img/web-hero.png)

---

## Contents

- [The problem](#the-problem)
- [The finding](#the-finding)
- [Quick start](#quick-start)
- [Architecture](#architecture)
- [The mandate flow](#the-mandate-flow)
- [Attacks and guards](#attacks-and-guards)
- [Scorecard](#scorecard)
- [What we did not solve](#what-we-did-not-solve)
- [Engineering log: bugs and fixes](#engineering-log-bugs-and-fixes)
- [Setup](#setup)
- [Project layout](#project-layout)

---

## The problem

Google's AP2 and NPCI's forthcoming UAP secure agent-initiated purchases with
cryptographically signed *mandates* proving a user authorised a transaction.

A signature proves that **someone signed something**. It does not prove that the
**content** being signed reflects what the user wanted. Everything upstream of the
signature — catalog data, tool results, inter-agent messages, and the approval screen
itself — is unsigned and manipulable. An attacker never needs to forge a signature.
They poison the context that determines what gets signed.

The source paper identifies 48 threats, 8 rated high-risk. This project reproduces
four threat families end-to-end against a working checkout, implements the guard layer
that blocks them, and reports with equal prominence the two scenarios it does not.

---

## The finding

The headline attack is **AM1, consent-capture poisoning**. Poisoned catalog text
shapes the constraint set the agent proposes *before the user approves anything*:

```
agent surveys the poisoned catalog
  └─ proposes a ceiling of 249,900 paise, with a justification lifted from merchant copy
      └─ approval screen shows the user their own stated 200,000 paise
          └─ user approves — and signs 249,900
              └─ every downstream check passes honestly
```

Running the same scenario in both modes shows the whole point at once — the vulnerable
run passes **every** check in the verifier pipeline and still moves the money, while the
guarded run stops at `scope.recheck`:

![The attack/block contrast](docs/img/web-contrast.png)

In text:

```
user stated budget          200,000 paise
approval screen showed      200,000 paise
mandate actually signed     249,900 paise     ← faithful=False, rendered_by=agent
cart charged                249,900 paise

ORDER CREATED order_TXtqM7yqt9MPT6 for 249900 paise (razorpay-test-mode)
— user overspent by 49900 paise while every signature verified and every
  downstream check passed honestly.
```

**There is no failed check to report, because nothing downstream is wrong.** The closed
mandate genuinely does fall within the open mandate's ceiling. The signature chain is
valid. The delegation is intact. The lie is in the premise.

This is why a verification-only defence structurally cannot catch this class of attack,
and why the mitigation has to live at the moment consent is captured rather than at the
moment a mandate is checked. The UI renders the verifier's full named check pipeline for
exactly this reason: in vulnerable mode all 16 checks show green and the order is still
created.

---

## Quick start

```bash
python demo.py            # one attack, run twice: exploited, then blocked
python demo.py --all      # every scenario, both modes, full scorecard
```

`MODE=vulnerable` and `MODE=guarded` execute the **same code paths**. The guard is
middleware that is either engaged or bypassed (`guard/__init__.py:build_guard`). You are
not comparing two programs; you are comparing one program with and without one layer.

![CLI attack contrast](docs/img/cli-contrast.png)

Other entry points:

```bash
python demo.py --purchase                   # the honest agent-driven purchase
python -m attacks.runner --evidence both    # full evidence log for both modes
uvicorn main:app                            # web UI on http://127.0.0.1:8000
```

Everything runs without credentials — see [Setup](#setup).

---

## Architecture

```
Demo surface (Rich CLI / static HTML page)
        │
   ShoppingAgent          LLM + 4 tools: search_catalog, add_to_cart, get_cart, checkout
        │
   MANDATE GUARD          ← MODE=vulnerable | guarded     the actual product
        │
   Signer ──────────────  private keys
   Independent Verifier ─ public keys only
        │
   Razorpay client        test mode
```

Four genuinely separate ES256 / P-256 keypairs: `user_key`, `agent_key`, `merchant_key`,
`trusted_surface_key`. The verifier is constructed with public keys only and raises
`PrivateKeyLeak` if handed anything containing `PRIVATE KEY`, so signer/verifier
separation cannot silently rot as the code changes.

**The guard is pure deterministic logic and never calls an LLM.** The agent proposes;
the guard decides. This is deliberate: an LLM judge is subject to the same injection as
the agent it judges, so using a model where a deterministic check suffices is a design
error rather than a shortcut.

---

## The mandate flow

Four mandate types, all ES256-signed JWTs.

| Mandate | Signed by | Commits to |
|---|---|---|
| Open Checkout | `user_key` | Spending ceiling, allowed merchants, allowed categories, expiry |
| Open Payment | `user_key` | Payment ceiling, allowed payees, step-up threshold |
| Closed Checkout | `agent_key` | `checkout_hash` over the canonical cart, amount, merchant, nonce |
| Closed Payment | `agent_key` | `transaction_id` (equals `checkout_hash`), amount, payee, risk attestation |

A fifth signed object, the **risk attestation**, is issued by `trusted_surface_key` —
which the shopping agent does not hold. That is what makes guard G3 enforceable: a
malicious agent can fabricate an unsigned `risk_data` blob, but it cannot mint an
attestation the verifier will accept.

The verifier runs a 15-step pipeline: signature checks first, then delegation and
binding, then policy. Each step is named so a block can be attributed to a specific
guard in the scorecard.

---

## Attacks and guards

| # | Attack | What it exploits | Threat | Guard |
|---|---|---|---|---|
| 1a | **Consent-capture poisoning** — catalog text shapes the constraint set before the user approves; the user is shown 200,000 and signs 249,900 | The approval surface is unsigned, and merchant text reaches the human as a reason to approve | F1 / T-1 | **G1a** |
| 1b | **Claimed constraints** — the agent asserts a widened scope and the naive verifier trusts the assertion | The verifier trusts a counterparty's claim rather than re-deriving from the user-signed original | F1 / T-1 via SR3 | **G1** |
| 2 | **Mandate replay** — resubmit a validly signed closed mandate | A signature cannot express "already used" | F4 / T-31 | **G2** |
| 3 | **`risk_data` spoofing** — the agent asserts `step_up_completed: true` for a transaction never challenged | Risk signals are unsigned, therefore unattributable | F4 / T-34 | **G3** |
| 4 | **Merchant substitution** — `merchant_a1pha` (digit one) for `merchant_alpha` | Any comparison looser than byte equality turns an allowlist into a suggestion | F3 / T-27 | **G4** |

| Guard | Mechanism |
|---|---|
| **G1a** | **Faithful consent capture.** The constraint set derives from the user's stated intent; an agent proposal may only ever *tighten* a value. The approval surface renders the exact structured number that will be signed. Merchant-supplied justification text is never shown as a reason to approve a larger number — that text is a persuasion channel from the attacker directly to the human. |
| **G1** | **Untrusted content boundary and deterministic scope re-check.** Catalog text is fenced as data, which raises the cost of an injection without eliminating it. The binding control is a re-check of the final cart against the *original user-signed constraints*; no catalog text is read on that path, so none can influence the outcome. |
| **G2** | **Single-use nonces and expiry.** Shared SQLite store in WAL mode; a `UNIQUE` constraint plus an atomic `INSERT` does the real work, so two concurrent replays cannot both succeed. A missing expiry fails closed. |
| **G3** | **Signed risk attestation.** Risk signals are accepted only inside an attestation that is signed by an authorised issuer, schema-valid, bound to *this* transaction id, and unexpired. Step-up necessity is decided from the amount — a value the verifier already knows independently — so an attestation can never argue that a challenge was unnecessary. |
| **G4** | **Exact-match merchant pinning.** Byte-for-byte comparison. No casefolding, no Unicode normalisation, no substring, no edit distance. Fails closed. |
| **G5** | **Independent verification.** Public keys only. `checkout_hash` is re-derived from the canonical cart rather than read out of the mandate under inspection. |
| **G6** | **Hash-chained audit log.** Each entry commits to the SHA-256 of its predecessor; `verify_chain()` detects modification, deletion and splicing. |

G5 is the architecturally significant one. In vulnerable mode, verification shares state
with signing. In guarded mode the verifier holds only public material and the pinned
constraint set.

---

## Scorecard

Generated by `python -m attacks.runner`. Every figure comes from an actual run against
the real pipeline. Successful attacks in vulnerable mode create real Razorpay test-mode
orders, and the order ids are printed so the claims can be checked against the
dashboard. Nothing here is hand-written.

![Scorecard](docs/img/web-scorecard.png)

The same run from the CLI:

![CLI scorecard](docs/img/cli-scorecard.png)

```
ATTACKS BLOCKED:      14/16    MISSED: 2/16
LEGITIMATE ALLOWED:   10/10    FALSE POSITIVES: 0
```

14/14 of the scenarios a guard actually claims. The other 2 are declared gaps with no
guard behind them.

### The false-positive suite

A guard that fails closed on everything blocks 16/16 attacks and is useless in
production. The second number answers the question the first one cannot: **does the
guard wrongly stop real customers?**

None of these ten is a happy path through the middle of the range. Each sits on a
boundary where a fail-closed check is most likely to over-fire.

| Legitimate scenario | Guard tested | Boundary being probed |
|---|---|---|
| `cart_exactly_at_cap` | G1 | Spending the entire budget to the paise — an off-by-one (`>` vs `>=`) blocks a max-budget customer |
| `agent_proposes_tighter_ceiling` | G1a | An agent asking for *less* authority must be honoured, not blanket-ignored |
| `exactly_at_step_up_threshold` | G3 | `amount >= threshold` — at-threshold demands a challenge, which must then clear |
| `just_below_step_up_threshold` | G3 | One paise under: must complete with no challenge at all |
| `two_purchases_one_session` | G2 | Distinct nonces under one authorisation must both be accepted |
| `purchase_near_expiry` | G2 | Freshness must not be over-eager 20 seconds before expiry |
| `second_allowlisted_merchant` | G4 | Exact matching must test the whole allowlist, not position zero |
| `multi_item_cart_with_quantity` | G5 | `checkout_hash` re-derivation over 2 lines and 3 units |
| `cheapest_item_baseline` | — | Sanity |
| `compliant_agent_flow` | — | The full tool path end to end |

The boundaries were verified to be real rather than comfortably inside the limit: the
at-cap cart has a margin of exactly 0 paise and one paise over is refused at
`scope.recheck`; the at-threshold amount equals the threshold exactly and the same
transaction without a completed challenge is refused by G3. A test that cannot fail
proves nothing.

Run it with `python -m attacks.runner`, which prints both tables.

Two notes on reading this honestly:

- `merchant_substitution_typosquat` is blocked by **G1, not G4**. The scope re-check
  fires before merchant pinning in the pipeline. G4 rejects it independently as well.
  The scorecard prints the guard that *actually fired* rather than the one we expected,
  and the pipeline was not reordered to make G4 look responsible.
- The two misses are real. They were found by attempting to block them and failing, not
  constructed to fail. `cross_verifier_replay` was a third miss until the consumed-nonce
  store was moved off per-instance memory; that is the intended lifecycle for everything
  in `attacks/a5_known_gaps.py`.

---

## What we did not solve

**Threat coverage: 4 of the paper's 48 threats**, across 4 threat families. Four
demonstrated end-to-end was preferred over eighteen half-implemented.

**The false-positive suite is 10 scenarios, not a statistical sample.** It covers the
boundaries most likely to over-fire, which is where over-blocking actually happens — but
0 false positives across 10 boundary cases is not the same claim as a measured
false-positive *rate* over real traffic.

### Two scenarios in our own scorecard get through

**`rendered_vs_signed_divergence` (F1 / T-7).** The cart the user reviewed is not the
cart that gets signed. G5 re-derives `checkout_hash` from the cart it is *given*, which
faithfully commits to the mutated cart — the hash is correct, the contents are not.
Nothing in the system ever recorded what the human looked at, so there is no reference
to diff against. Closing this requires the Trusted Surface to sign the rendered cart at
review time and the verifier to require that signature. That is real work and it was not
built. Note this is a *different instance* of the divergence pattern than G1a addresses:
G1a binds the open mandate's **ceiling**; this is the closed mandate's **contents**.

**`compromised_agent_key_in_scope_spend`.** If the signing key itself is compromised,
every downstream signature is genuinely valid and no content-verification layer can
distinguish the attacker from the legitimate agent. This is an authentication and
key-management problem, not a mandate-integrity one. What the guard still does is bound
the loss to the approved ceiling — which is precisely why G1a keeping that ceiling
faithful matters.

### Attack 1b is a simplified model of the threat

Scenario `catalog_injection_claimed_constraints` models vulnerable-mode corruption as a
*claimed-field trust failure* rather than the paper's upstream consent-capture
poisoning. The general principle — independent re-derivation versus trusting supplied
assertions, the paper's SR3 — is the same; the attack surface is simplified, and a
reader is right to ask why any verifier would trust a field named `asserted_constraints`.
Scenario 1a (`consent_poisoning`) is the faithful AM1 version and is the one to judge
this project on. Both were kept because they fail in different places and are blocked by
different mechanisms.

### Other simplifications

- **SD-JWT selective disclosure is not implemented.** Mandates are plain ES256 JWTs.
  Real AP2 uses SD-JWT; every field in our mandates is visible to every party that sees
  one.
- **The UAP registry is simulated.** UAP was announced in July 2026 with no public spec
  or implementation, so there is nothing to be compliant with. `KeyRegistry` is an
  in-memory stand-in for what would be an issuer directory.
- **Single-process trust model.** One process holds the signer, the verifier and the
  guard. Key separation is enforced in code, not by process or hardware isolation.
- **Nonce coordination is single-host.** G2 uses a shared SQLite store, which fixes
  replay across verifier instances on one machine. Genuine multi-region deployment needs
  a distributed store with first-writer-wins consensus. Two hosts with two files
  reintroduces the bug that was fixed.
- **No cross-tenant isolation.** One user, one session, no accounts or auth.
- **No dispute, reversal or refund mechanism.** Orders are created; contested orders are
  not handled.
- **Prompt injection is not solved, and no such claim is made.** G1's content fencing
  raises the cost of an injection; it does not eliminate it. The binding control is the
  deterministic post-check, which is why the guard contains no model.
- **The deterministic agent is a worst-case stand-in, not evidence about real models.**
  With no LLM key configured, attack 1 runs against a scripted agent written to be
  *maximally injectable* — it obeys catalog instructions every time. That is deliberately
  harder for the guard than a real model that might resist on its own, but it is not
  evidence that any particular model falls for the injection. Attacks 2–4 involve no LLM
  at all; they are protocol-level.
- **Reproducibility is weaker than intended.** Gemini's OpenAI-compatible endpoint
  rejects `seed`, so LLM runs rely on `temperature=0` alone, which is not a hard
  determinism guarantee. Attacks 2–4 and the entire guard layer are fully deterministic.

---

## Engineering log: bugs and fixes

Real defects hit during the build, with the steps that reproduced them.

### 1. `razorpay==1.4.2` fails to import on Python 3.12

**Symptom**
```
File "razorpay/client.py", line 4, in <module>
    import pkg_resources
ModuleNotFoundError: No module named 'pkg_resources'
```

**Reproduction** — create a 3.12 venv, install the pinned SDK, import it:
```bash
python3.12 -m venv .venv && .venv/bin/pip install razorpay==1.4.2
.venv/bin/python -c "import razorpay"
```

**Cause** — the SDK imports `pkg_resources`, part of `setuptools`. Python 3.12 venvs no
longer ship `setuptools` by default (PEP 632 deprecation), so the import fails on a
clean environment.

**Fix** — upgraded to `razorpay==2.0.1`, which dropped the dependency. Pinning
`setuptools` back in would have masked a deprecated import rather than removing it.

**Verified** — `.venv/bin/python -c "import razorpay"` succeeds; the environment check
created a live test-mode order `order_TXiNeZShic1EMp`.

---

### 2. Vulnerable mode was not actually vulnerable

**Symptom** — attack 1 blocked in *both* modes, so there was no contrast to demonstrate:
```
[vulnerable] cart=249900 cap=200000 authorized=False guard=G5
             DECLINED -- payment.ceiling: 249900 paise exceeds the payment cap 200000
[guarded   ] cart=249900 cap=200000 authorized=False guard=G1
             DECLINED -- scope.recheck: cart total 249900 paise exceeds user cap 200000
```

**Reproduction** — run the injection scenario in vulnerable mode and observe that the
ceiling check fires regardless of mode.

**Cause** — a modelling error rather than a coding one. The naive path still enforced
the spending cap independently, which is not what the paper describes. Its claim is that
the naive verifier trusts values the *agent* supplies, because everything upstream of
signing is unsigned.

**Fix** — two stages. First, the guard was given authority over *whose* constraints
govern a transaction (`effective_constraints`), so vulnerable mode consumes the agent's
assertion while guarded mode discards it unread. Then, after review, attack 1 was
rebuilt as the faithful AM1 version: poison enters at consent capture
(`guard/consent_capture.py`), the user signs an inflated ceiling, and every downstream
check passes honestly. The simplified version was retained as a separate, explicitly
labelled scenario.

**Verified** — vulnerable mode now creates a real order for 249,900 paise against a
200,000 paise stated budget; guarded mode declines at `scope.recheck`.

---

### 3. Gemini's OpenAI-compatible endpoint rejects `seed`

**Symptom**
```
openai.BadRequestError: Error code: 400 - Invalid JSON payload received.
Unknown name "seed": Cannot find field.
```

**Reproduction** — point the OpenAI SDK at
`https://generativelanguage.googleapis.com/v1beta/openai/` and pass `seed=1337` to
`chat.completions.create`.

**Cause** — the compatibility layer implements a subset of the OpenAI schema and rejects
unknown fields outright rather than ignoring them.

**Fix** — `LLMShoppingAgent._create_with_retries` attempts the call with `seed`, and on a
`BadRequestError` mentioning it, drops the parameter permanently and records
`supports_seed = False`.

**Verified** — the agent completes a full tool-calling loop. The flag is surfaced rather
than hidden, because it weakens the reproducibility claim; the limitations section states
that determinism now rests on `temperature=0` alone.

---

### 4. Gemini 3.x requires `thought_signature` on multi-turn tool calls

**Symptom**
```
openai.BadRequestError: Error code: 400 - Function call is missing a thought_signature
in functionCall parts. This is required for tools to work correctly...
```

**Reproduction** — run a two-turn tool-calling loop: send tools, receive a `tool_calls`
response, append a hand-built assistant message with `id` / `name` / `arguments`, append
the tool result, then call again.

**Cause** — Gemini 3.x attaches an opaque `thought_signature` inside
`tool_calls[].extra_content.google`. Reconstructing the assistant message from the three
fields the OpenAI schema documents silently discards it, and the next request is
rejected. Inspecting `message.model_dump()` showed the field:
```json
{"tool_calls": [{"id": "call_1732787",
  "function": {"name": "search_catalog", "arguments": "{\"query\":\"running shoes\"}"},
  "extra_content": {"google": {"thought_signature": "EvcCCvQCARFNMg8SwgmOOqr..."}}}]}
```

**Fix** — echo the provider's own message back verbatim with
`messages.append(message.model_dump(exclude_none=True))` instead of rebuilding it.

**Verified** — a four-call agent loop completes: two searches, `add_to_cart`, `get_cart`,
`checkout`, producing order `order_TXiYYgcd0nawgJ`.

---

### 5. `database is locked` after making the nonce store shared

**Symptom**
```
File "guard/nonce_store.py", line 47, in consume
    self._conn.execute(
sqlite3.OperationalError: database is locked
```

**Reproduction** — point `NonceStore` at a file rather than `:memory:`, then run two
scenarios in one process so several verifier instances hold connections concurrently.

**Cause** — Python's `sqlite3` opens an implicit transaction before DML and holds it
until `commit()`. With multiple long-lived connections to one file, writers block each
other. Enabling WAL and `busy_timeout` alone did **not** resolve it, because the lock was
held by an open transaction rather than by contention the timeout could wait out.

**Fix** — `isolation_level=None` on both stores, putting the connection in autocommit so
each `INSERT` commits immediately and releases its lock. WAL and `busy_timeout` were kept
as defence in depth.

**Verified** — all four replay scenarios pass in both modes with no lock errors, and the
full 16-scenario runner completes cleanly.

---

### 6. Nonce store did not survive horizontal scaling

**Symptom** — a mandate already consumed by one verifier was honoured by a second,
producing two real orders from one authorisation. This shipped as a *declared miss*
before it was fixed.

**Reproduction** — complete a purchase, then submit the same signed mandates to a second
`IndependentVerifier` built with its own guard:
```python
replica = IndependentVerifier(session.registry.public_only(), build_guard(mode))
outcome = replica.authorize(open_checkout_jwt, open_payment_jwt,
                            first.closed_checkout_jwt, first.closed_payment_jwt, cart)
# outcome.authorized is True — the nonce was never seen by this instance
```

**Cause** — `MandateGuard` opened both the nonce store and the audit chain at
`:memory:` from a single `db_path` argument. That conflated two different concerns: the
consumed-nonce set is *shared infrastructure* every verifier must agree on, while the
audit chain is legitimately per-session. Horizontal scaling therefore gave each replica
an empty consumed set.

**Fix** — separated the two. The nonce store defaults to the configured `DB_PATH` and is
shared across instances; the audit chain stays per-session. Single-use is enforced by a
`UNIQUE` constraint and an atomic `INSERT`, so two concurrent replays cannot both win.

**Verified** — `cross_verifier_replay` moved from `MISSED` to `BLOCKED (G2)` and was
promoted out of `attacks/a5_known_gaps.py` into the replay module. The remaining
multi-region limitation is disclosed rather than papered over.

---

### 7. Scorecard totals silently dropped in the web UI

**Symptom** — the scorecard table rendered, but the `BLOCKED 14/16 MISSED 2/16` summary
beneath it never appeared. Caught by inspecting a screenshot, not by an error.

**Reproduction** — open the web UI, click **Full scorecard**, and observe that
`#scoreout .totals` does not exist in the DOM.

**Cause** — the page's `el()` helper builds a fragment and returns `d.firstChild`. The
template passed a `<table>` followed by a sibling `<div class="totals">`, so only the
table survived. No error was raised, in the browser console or anywhere else.

**Fix** — wrapped the template in a single container element, with a comment at the call
site recording the constraint.

**Verified** — `page.inner_text('#scoreout .totals')` returns
`BLOCKED 14/16   MISSED 2/16`, and the regenerated screenshot shows it.

---

## Setup

Requires Python 3.11+ (developed on 3.12).

```bash
python3.12 -m venv .venv
.venv/bin/pip install -r requirements.txt
cp .env.example .env
```

**The demo runs with no credentials.** The payment rail falls back to a clearly-labelled
simulator and the agent to the deterministic stub, so the attack/block contrast
reproduces on a bare clone. This was verified by cloning to a fresh directory and running
the suite with empty keys: identical 14/16 scorecard.

Add credentials to `.env` to exercise the live paths:

| Variable | Notes |
|---|---|
| `RAZORPAY_KEY_ID` / `RAZORPAY_KEY_SECRET` | Razorpay dashboard, **Test Mode**. The key id must start with `rzp_test_`; the client refuses to construct otherwise. |
| `LLM_API_KEY` | Any OpenAI-compatible endpoint. |
| `LLM_BASE_URL` | For Gemini: `https://generativelanguage.googleapis.com/v1beta/openai/` |
| `LLM_MODEL` | e.g. `gemini-3.5-flash` |

Verify:

```bash
.venv/bin/python demo.py --purchase    # agent-driven purchase, end to end
.venv/bin/python demo.py               # the attack/block contrast
```

`.env` is gitignored; only `.env.example` is committed.

To regenerate the screenshots in this README:

```bash
.venv/bin/pip install playwright && .venv/bin/playwright install chromium
.venv/bin/uvicorn main:app --port 8000 &
.venv/bin/python docs/capture.py
```

---

## Project layout

```
config.py                       env-driven settings, MODE flag
mandates/  crypto.py            ES256 keys, canonical JSON, sign/verify
           schemas.py           4 mandate types + consent-capture models
           signer.py            mandate construction; TrustedSurface
           verifier.py          independent verifier (public keys only)
guard/     __init__.py          mode dispatch: MandateGuard | BypassedGuard
           consent_capture.py   G1a
           untrusted_content.py G1
           nonce_store.py       G2
           risk_attestation.py  G3
           merchant_pinning.py  G4
           audit_chain.py       G6
agent/     shopping_agent.py    LLM loop + deterministic stub
           session.py           checkout orchestration
catalog/   products.json        2 poisoned listings, 1 typo-squat merchant
attacks/   a1..a5, runner.py    attack scenarios + scorecard generation
           legit_suite.py       false-positive suite (10 boundary cases)
docs/      capture.py           regenerates the README screenshots
results/   scorecard.json       generated, committed
```

---

## Source

> Aviv, Gandhi, Bitton & Shabtai. *Beyond the Mandate: A Systematic Security Analysis of
> the Agent Payments Protocol (AP2).* arXiv:2608.23858. Ben-Gurion University of the
> Negev and Intuit.

Payments are Razorpay **test mode** only. No KYC, no live keys, no real money.
