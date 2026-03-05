"""Shim: dashboard moved to apps.dashboard.main. Preserves streamlit run promptheus.interfaces.dashboard."""

from apps.dashboard.main import run

if __name__ == "__main__":
    run()
