"""Optional lightweight Streamlit dashboard for MARVIN.

Run with:
    pip install -e ".[dashboard]"
    streamlit run dashboard/app.py

This is a *visualisation only* layer over the same simulation the CLI uses. It
shows risk over time, the selected policy over time, key rotations, and the full
audit trail. It is intentionally thin so it never blocks the core build.
"""

from __future__ import annotations

import sys
from pathlib import Path

# Allow running via `streamlit run dashboard/app.py` from the repo root.
sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

import pandas as pd  # noqa: E402
import streamlit as st  # noqa: E402

from marvin.domain.enums import Scenario  # noqa: E402
from marvin.simulation.runner import SimulationRunner  # noqa: E402

RISK_TO_NUM = {"LOW": 1, "MEDIUM": 2, "HIGH": 3, "CRITICAL": 4}


def main() -> None:
    st.set_page_config(page_title="MARVIN", layout="wide")
    st.title("MARVIN — Adaptive Cybersecurity Simulation")
    st.caption(
        "Simulation only. Not production quantum cryptography, QKD hardware, or "
        "regulated security infrastructure."
    )

    with st.sidebar:
        st.header("Simulation controls")
        scenario = st.selectbox(
            "Scenario", [s.value for s in Scenario], index=0
        )
        ticks = st.slider("Ticks", min_value=5, max_value=60, value=15)
        use_seed = st.checkbox("Deterministic (seeded)", value=True)
        seed = st.number_input("Seed", value=7, step=1) if use_seed else None
        run = st.button("Run simulation", type="primary")

    if not run:
        st.info("Configure a scenario in the sidebar and click **Run simulation**.")
        return

    runner = SimulationRunner()
    result = runner.run_session(
        scenario=Scenario(scenario),
        ticks=ticks,
        seed=int(seed) if seed is not None else None,
    )

    rows = []
    for snap in result.snapshots:
        rows.append(
            {
                "tick": snap.tick_number,
                "risk_level": snap.risk_level.value,
                "risk_num": RISK_TO_NUM[snap.risk_level.value],
                "risk_score": snap.risk_score,
                "policy": snap.selected_policy.value if snap.selected_policy else "-",
                "rotated": snap.key_event.rotated,
                "quarantined": snap.key_event.quarantined,
                "next_action": snap.next_action,
                "explanation": snap.explanation,
            }
        )
    df = pd.DataFrame(rows).set_index("tick")

    c1, c2, c3 = st.columns(3)
    c1.metric("Ticks", result.ticks)
    c2.metric("Peak risk", df["risk_level"].iloc[df["risk_num"].argmax()])
    c3.metric("Key rotations", int(df["rotated"].sum()))

    st.subheader("Risk over time")
    st.line_chart(df[["risk_score"]])
    st.bar_chart(df[["risk_num"]])

    st.subheader("Selected policy over time")
    st.dataframe(df[["risk_level", "policy", "rotated", "quarantined"]])

    st.subheader("Key rotations")
    rotations = df[df["rotated"] | df["quarantined"]][
        ["policy", "rotated", "quarantined", "next_action"]
    ]
    if rotations.empty:
        st.write("No key rotations in this run.")
    else:
        st.dataframe(rotations)

    st.subheader("Audit trail")
    if result.audit_logger is not None:
        st.json(result.audit_logger.export())


if __name__ == "__main__":
    main()
