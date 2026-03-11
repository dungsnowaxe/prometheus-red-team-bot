import { useState, useEffect } from "react";
import { Card, CardContent, CardHeader, CardTitle, CardDescription } from "@/components/ui/card";
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";
import { ScanModeSelector } from "@/components/ScanModeSelector";
import { ScanInputs } from "@/components/ScanInputs";
import { ScanControls } from "@/components/ScanControls";
import { LogViewer } from "@/components/LogViewer";
import { ResultsTable } from "@/components/ResultsTable";

const MODE_LABELS = { url: "URL scan", agent: "Agent scan", pr: "PR review" };

function App() {
  const [cliPathOverride, setCliPathOverrideState] = useState("");
  const [loaded, setLoaded] = useState(false);
  const [mode, setMode] = useState("url");
  const [targetUrl, setTargetUrl] = useState("");
  const [agentPath, setAgentPath] = useState("");
  const [agentModel, setAgentModel] = useState("sonnet");
  const [agentDast, setAgentDast] = useState(false);
  const [agentDastUrl, setAgentDastUrl] = useState("");
  const [agentConfirmLarge, setAgentConfirmLarge] = useState(false);
  const [prPath, setPrPath] = useState("");
  const [prRange, setPrRange] = useState("");
  const [prLastN, setPrLastN] = useState(1);
  const [running, setRunning] = useState(false);
  const [runLabel, setRunLabel] = useState("");
  const [result, setResult] = useState(null);
  const [combinedLog, setCombinedLog] = useState("");
  const [scanActive, setScanActive] = useState(false);

  useEffect(() => {
    if (window.electronAPI?.getCliPathOverride) {
      window.electronAPI.getCliPathOverride().then((v) => {
        setCliPathOverrideState(v || "");
        setLoaded(true);
      });
    } else {
      setLoaded(true);
    }
  }, []);

  useEffect(() => {
    if (!window.electronAPI?.onScanOutput) return;
    const handler = ({ event, data }) => {
      if (!scanActive) return;
      if (event === "stdout" || event === "stderr") setCombinedLog((prev) => prev + data);
    };
    window.electronAPI.onScanOutput(handler);
    // Note: electronAPI.onScanOutput doesn't provide unsubscribe mechanism
    // We rely on scanActive flag to prevent processing stale events
    return () => {
      // Cleanup placeholder - actual listener cleanup handled by scanActive flag
    };
  }, [scanActive]);

  const saveCliPathOverride = (value) => {
    setCliPathOverrideState(value);
    window.electronAPI?.setCliPathOverride?.(value);
  };

  const runScan = async (scanFn, label) => {
    setRunning(true);
    setRunLabel(label);
    setResult(null);
    setCombinedLog("");
    setScanActive(true);
    try {
      const res = await scanFn();
      setResult(res);
    } catch (e) {
      setResult({ code: -1, stderr: String(e?.message || e), results: undefined });
    } finally {
      setRunning(false);
      setRunLabel("");
      setScanActive(false);
    }
  };

  const runCurrent = () => {
    if (mode === "url") {
      const url = targetUrl.trim();
      if (!url) return;
      runScan(() => window.electronAPI?.runScan?.(url), "URL scan");
    } else if (mode === "agent") {
      const path = agentPath.trim();
      if (!path) return;
      runScan(
        () =>
          window.electronAPI?.runAgentScan?.({
            targetPath: path,
            model: agentModel || undefined,
            dast: agentDast,
            dastUrl: agentDast ? agentDastUrl.trim() || undefined : undefined,
            confirmLargeScan: agentConfirmLarge,
          }),
        "Agent scan"
      );
    } else {
      const path = prPath.trim();
      if (!path) return;
      runScan(
        () =>
          window.electronAPI?.runPrReview?.({
            path,
            range: prRange.trim() || undefined,
            lastN: prLastN > 0 ? prLastN : 1,
          }),
        "PR review"
      );
    }
  };

  const cancelScan = () => {
    setScanActive(false);
    window.electronAPI?.cancelScan?.();
    setRunning(false);
    setRunLabel("");
    setCombinedLog((prev) => prev + "\n--- Scan cancelled ---\n");
  };

  const canRun = () => {
    if (mode === "url") return targetUrl.trim().length > 0;
    if (mode === "agent") return agentPath.trim().length > 0;
    return prPath.trim().length > 0;
  };

  return (
    <div className="mx-auto max-w-3xl space-y-4 p-6">
      <h1 className="text-2xl font-bold tracking-tight">Promptheus</h1>

      <Card>
        <CardHeader>
          <CardTitle>Settings</CardTitle>
          <CardDescription>
            Optional CLI path override (leave blank to use bundled CLI or PATH).
          </CardDescription>
        </CardHeader>
        <CardContent>
          <div className="space-y-2">
            <Label htmlFor="cli-path">CLI Path</Label>
            <Input
              id="cli-path"
              type="text"
              value={cliPathOverride}
              onChange={(e) => setCliPathOverrideState(e.target.value)}
              onBlur={(e) => saveCliPathOverride(e.target.value)}
              placeholder="e.g. promptheus or /path/to/promptheus"
              disabled={!loaded}
            />
          </div>
        </CardContent>
      </Card>

      <Card>
        <CardHeader>
          <CardTitle>Scan Configuration</CardTitle>
          <CardDescription>Select a scan mode and configure its parameters.</CardDescription>
        </CardHeader>
        <CardContent className="space-y-4">
          <ScanModeSelector mode={mode} onModeChange={setMode} disabled={running} />

          <div className="rounded-lg border bg-muted/30 p-4">
            <h3 className="mb-3 text-sm font-medium">{MODE_LABELS[mode]}</h3>
            <ScanInputs
              mode={mode}
              disabled={running}
              urlScan={{ targetUrl, setTargetUrl }}
              agentScan={{
                agentPath, setAgentPath,
                agentModel, setAgentModel,
                agentDast, setAgentDast,
                agentDastUrl, setAgentDastUrl,
                agentConfirmLarge, setAgentConfirmLarge,
              }}
              prReview={{ prPath, setPrPath, prRange, setPrRange, prLastN, setPrLastN }}
            />
          </div>

          <ScanControls
            running={running}
            canRun={canRun()}
            runLabel={runLabel}
            onRun={runCurrent}
            onCancel={cancelScan}
          />
        </CardContent>
      </Card>

      {(combinedLog || running) && (
        <Card>
          <CardHeader>
            <CardTitle>CLI Output</CardTitle>
          </CardHeader>
          <CardContent>
            <LogViewer log={combinedLog} visible={true} />
          </CardContent>
        </Card>
      )}

      {result && (
        <Card>
          <CardHeader>
            <CardTitle>Results</CardTitle>
          </CardHeader>
          <CardContent>
            <ResultsTable result={result} />
          </CardContent>
        </Card>
      )}
    </div>
  );
}

export default App;
