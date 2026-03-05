"""FastAPI server: run scan and list payloads for desktop/mobile clients."""

from typing import Any

from fastapi import FastAPI, HTTPException
from pydantic import BaseModel, HttpUrl

from promptheus.adapters.rest import RestAPITarget
from promptheus.core.attacks import load_payloads
from promptheus.core.engine import RedTeamEngine

app = FastAPI(title="PROMPTHEUS API", description="Red-team scan API for desktop/mobile clients")


class ScanRequest(BaseModel):
    """Target URL to scan."""

    target_url: HttpUrl


class ScanResultItem(BaseModel):
    """Single payload result for JSON response."""

    payload_id: str
    name: str
    vulnerable: bool
    severity: str
    reasoning: str


class ScanResponse(BaseModel):
    """Full scan report."""

    results: list[ScanResultItem]


@app.get("/health")
def health() -> dict[str, str]:
    """Liveness check."""
    return {"status": "ok"}


@app.get("/payloads")
def list_payloads() -> list[dict[str, Any]]:
    """List available payloads (id, name)."""
    payloads = load_payloads()
    return [{"id": p.get("id", ""), "name": p.get("name", "")} for p in payloads]


@app.post("/scan", response_model=ScanResponse)
def run_scan(req: ScanRequest) -> ScanResponse:
    """Run red-team scan against target URL. Returns report."""
    url = str(req.target_url)
    try:
        adapter = RestAPITarget(url)
        engine = RedTeamEngine(adapter)
        report = engine.run_scan(verbose_console=False)
    except Exception as e:
        raise HTTPException(status_code=400, detail=f"Scan failed: {e!s}") from e
    return ScanResponse(
        results=[
            ScanResultItem(
                payload_id=r.payload_id,
                name=r.name,
                vulnerable=r.vulnerable,
                severity=r.severity,
                reasoning=r.reasoning,
            )
            for r in report.results
        ]
    )
