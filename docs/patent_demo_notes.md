# MARVIN — Patent Demonstration Notes

These notes frame MARVIN for an early **patent demonstration**, technical
storytelling, architecture validation, and future product exploration. They
describe *what the prototype demonstrates* and *how it is designed to extend*
into real systems, while being explicit about its simulation boundaries.

> **Important scope statement.** MARVIN is a *simulation*. It does not implement
> production quantum cryptography, QKD hardware behavior, or regulated security
> infrastructure, and it performs no real encryption. It demonstrates the
> **adaptive decision logic** of an AI-driven cryptographic orchestration system.

## What MARVIN demonstrates

### 1. Adaptive cryptographic orchestration
MARVIN shows a closed control loop that continuously adjusts cryptographic
protection during an *active* communication session, rather than configuring
encryption once at session start. The orchestrator
(`AdaptiveSecurityOrchestrator`) runs the full
*Observe → Score → Reason → Select → Rotate → Apply → Log* cycle every tick.

### 2. Dynamic policy selection based on live risk
The `CryptoPolicyEngine` chooses among a spectrum of simulated policies
(standard AEAD, low-latency cipher, frequent rotation, hybrid post-quantum,
quantum-escalated, and session quarantine) as a direct function of a live,
scored risk assessment — not static configuration. Strong signals (suspected
interception, restricted data, degraded links) override the base mapping,
demonstrating *context-aware escalation*.

### 3. Quantum entropy modelled as a replaceable provider
The `QuantumEntropyProvider` is intentionally small and sits behind an
`EntropyProvider` interface. The prototype models the *role* of a quantum
randomness source (entropy material, nonces, rotation jitter, a confidence
score) so a real **QRNG API** can be dropped in without changing the
orchestration logic. The simulated source is always clearly labelled.

### 4. Explainable audit logs
Every decision is justified. The `ThreatScoringEngine` attaches human-readable
`reasons` to each score; the `CryptoPolicyEngine` attaches `rationale` to each
policy; and the `AuditLogger` writes a structured, replayable `AuditEvent` per
tick (JSON-lines for downstream ingestion). This supports defensible,
explainable automated security decisions.

### 5. Moving target defense behavior
Protection is not static. Keys rotate on policy change, explicit rekey, and
expiry; rotation intervals tighten as risk rises; entropy-driven jitter varies
the rotation cadence; and high-risk sessions can be quarantined. The result is a
continuously shifting attack surface — the essence of moving-target defense.

### 6. Governed multi-model security council
MARVIN can convene several *independent* reasoning engines (OpenAI, Gemini,
Llama/Meta, optionally Claude/Mythos) as advisors that review identical
telemetry and return a shared structured recommendation schema. A deterministic
consensus + governance + decision pipeline then:

- measures agreement and **disagreement** across the models,
- applies **hard guardrails** that no model can override,
- escalates only with multi-advisor support (no lone model drives an action),
- takes the **conservative** path on splits and flags **human review**, and
- records every advisor opinion and the governed outcome in the audit log.

The defensible thesis — *"LLMs advise; MARVIN governs"* — is the differentiator:
several independent reasoning engines interpret ambiguity while a transparent,
testable policy core retains final authority. See
[`security_council.md`](security_council.md) for the worked example and the
claims-surface discussion.

## Illustrative claims surface (for discussion, not legal text)

The prototype concretely exercises ideas such as:

- A method for **continuously selecting and switching cryptographic policy**
  during an active session based on a live, explainable risk score derived from
  multi-signal telemetry.
- A **risk-proportional key-rotation** mechanism whose cadence and lineage adapt
  to scored threat conditions, including entropy-source-driven jitter.
- An **escalation-and-quarantine** decision process triggered by specific
  high-severity signals (e.g. suspected interception) that overrides a baseline
  risk-to-policy mapping.
- A **provider-abstracted entropy interface** allowing substitution of a
  quantum random number generator without altering orchestration logic.
- An **explainable audit pipeline** producing per-decision justification suitable
  for compliance review and SIEM ingestion.

## Designed extension points (toward a real product)

| Simulated today | Replace with |
| --- | --- |
| `QuantumEntropyProvider` | Real **QRNG API** (e.g. hardware/cloud entropy service). |
| Policy *descriptors* | Real **post-quantum** + classical hybrid suites (ML-KEM, etc.). |
| `SessionKey` descriptors | Keys backed by an **HSM / KMS**. |
| `AuditLogger` JSONL | Streaming to a real **SIEM** (Splunk, Elastic, Sentinel). |
| `requires_reauthentication` flag | Step-up auth via a **zero-trust identity** provider. |
| Weighted-sum scorer | A **learned risk model** retaining explainability. |
| Offline advisor personas | Live **OpenAI / Gemini / Llama / Anthropic** APIs (structured outputs). |
| Scripted telemetry | Real **SIEM / EDR / IAM / cloud** log ingestion into the normalizer. |

## How to run the demonstration

```bash
pip install -e .
python -m marvin simulate --scenario SUSPECTED_INTERCEPTION --ticks 12 --seed 7
```

Reviewers will see MARVIN detect rising risk, explain it, escalate the crypto
policy, rotate then invalidate keys, log every decision, and continue adapting —
all reproducibly under a fixed seed. The accompanying audit log
(`--jsonl audit.jsonl`) provides the full machine-readable trace.
