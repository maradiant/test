# MARVIN — Simulated Threat Model

This document describes the threats MARVIN *simulates*, how they map to
telemetry signals and scenarios, and the boundaries of the simulation.

> **Scope.** These are *simulated* threats used to drive adaptive decision
> logic. MARVIN does not detect or defend against real attacks and makes no
> security guarantees.

## Telemetry signals

Each tick, MARVIN observes a `TelemetrySnapshot`. The risk-relevant fields are:

| Signal | Meaning | Risk direction |
| --- | --- | --- |
| `anomaly_score` (0..1) | Behavioural/statistical anomaly on the channel. | Higher → riskier |
| `endpoint_trust_score` (0..1) | Confidence the endpoint is legitimate. | Lower → riskier |
| `failed_auth_attempts` | Recent authentication failures. | Higher → riskier |
| `geo_velocity_risk` (0..1) | Improbable travel / impossible-journey signal. | Higher → riskier |
| `suspected_interception` (bool) | Indicator of a man-in-the-middle. | True → strong escalation |
| `data_sensitivity` | Classification of in-flight data. | Higher class → riskier |
| `adversary_pressure` (0..1) | Aggregate hostile activity directed at the session. | Higher → riskier |
| `previous_incident_count` | Prior incidents on this session. | Higher → riskier |
| `network_latency_ms`, `packet_loss_percent` | Link quality. | Degraded → latency-aware policy + lower confidence |
| `traffic_volume` | Relative throughput. | Context (e.g. bulk transfer) |

## Modelled threat scenarios

| Scenario | Narrative | Dominant signals |
| --- | --- | --- |
| `LOW_RISK_NORMAL_OPERATION` | Healthy session, trusted endpoint. | All baseline/low. |
| `CREDENTIAL_STUFFING` | Repeated failed auth from improbable geo velocity. | `failed_auth_attempts`, `geo_velocity_risk`, low trust. |
| `SUSPECTED_INTERCEPTION` | Man-in-the-middle: jitter, anomalies, intercept flag. | `suspected_interception`, anomaly, latency/loss. |
| `HIGH_VALUE_DATA_TRANSFER` | Bulk transfer of restricted data. | `data_sensitivity = RESTRICTED`, high `traffic_volume`. |
| `DEGRADED_NETWORK` | Poor link quality. | `network_latency_ms`, `packet_loss_percent`. |
| `CRITICAL_ATTACK_CHAIN` | Multi-stage active attack. | Low trust, high pressure, interception, prior incidents. |

Scenarios marked as escalating ramp their indicators upward over the first ~10
ticks so an unfolding attack looks progressive rather than constant.

## How threats drive responses

1. **Scoring.** Signals are normalised, weighted, and summed into a 0..1 score
   mapped to `LOW/MEDIUM/HIGH/CRITICAL`. Suspected interception floors risk at `HIGH`.
2. **Policy.** Risk level selects a base policy; strong signals escalate it:
   - Interception → at least hybrid post-quantum (quarantine at CRITICAL).
   - Collapsed trust or extreme adversary pressure at CRITICAL → quarantine.
   - Restricted data → raise protection floor, tighten rotation.
   - Degraded network at low/medium risk → low-latency ChaCha20-Poly1305.
3. **Keys.** Higher risk shortens rotation intervals; quarantine invalidates keys.
4. **Posture.** Reauthentication and quarantine flags are applied and persisted.

## Response spectrum (simulated policies)

| Policy | Use | Latency impact |
| --- | --- | --- |
| `STANDARD_AES_256_GCM` | Routine, low risk. | LOW |
| `CHACHA20_POLY1305_LOW_LATENCY` | Degraded links. | LOW |
| `AES_256_GCM_FREQUENT_ROTATION` | Medium risk / restricted data. | MEDIUM |
| `HYBRID_POST_QUANTUM_MODE` | High risk / interception (reauth). | MEDIUM |
| `QUANTUM_ESCALATED_MODE` | Critical risk, aggressive rekeying. | HIGH |
| `SESSION_QUARANTINE` | Critical + interception / collapsed trust. | HIGH |

## Out of scope / non-goals

- Real attack detection, prevention, or forensics.
- Real key management, encryption, or transport security.
- Real quantum hardware or QKD.
- Regulatory compliance certification.
- Adversary modelling beyond the scripted telemetry scenarios.

These boundaries are intentional: MARVIN demonstrates *decision logic*, and each
boundary is a documented integration point for a future real implementation
(see `patent_demo_notes.md`).
