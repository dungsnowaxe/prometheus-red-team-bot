"""Streamlit dashboard: Target URL input, Start Attack, dataframe with Vulnerable highlighted."""

import streamlit as st

from promptheus.adapters.rest import RestAPITarget
from promptheus.core.engine import RedTeamEngine


def run() -> None:
    st.set_page_config(page_title="PROMPTHEUS Red-Team", layout="wide")
    st.title("PROMPTHEUS Red-Team Dashboard")
    target_url = st.text_input("Target URL", placeholder="https://your-api.com/chat")
    if st.button("Start Attack"):
        if not target_url:
            st.error("Please enter a Target URL.")
            return
        with st.spinner("Running scan..."):
            adapter = RestAPITarget(target_url)
            engine = RedTeamEngine(adapter)
            report = engine.run_scan(verbose_console=False)
        import pandas as pd

        rows = [
            {
                "Payload": r.name,
                "Verdict": "Vulnerable" if r.vulnerable else "Safe",
                "Severity": r.severity,
                "Reasoning": r.reasoning,
            }
            for r in report.results
        ]
        df = pd.DataFrame(rows)

        def highlight_vulnerable(row):
            if row["Verdict"] == "Vulnerable":
                return ["background-color: #ffcccc"] * len(row)
            return [""] * len(row)

        st.dataframe(df.style.apply(highlight_vulnerable, axis=1), use_container_width=True)


if __name__ == "__main__":
    run()
