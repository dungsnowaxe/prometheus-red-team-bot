import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";
import { Checkbox } from "@/components/ui/checkbox";

function UrlScanInputs({ targetUrl, setTargetUrl, disabled }) {
  return (
    <div className="space-y-2">
      <Label htmlFor="target-url">Target URL</Label>
      <Input
        id="target-url"
        type="url"
        value={targetUrl}
        onChange={(e) => setTargetUrl(e.target.value)}
        placeholder="https://example.com/api"
        disabled={disabled}
      />
    </div>
  );
}

function AgentScanInputs({
  agentPath, setAgentPath,
  agentModel, setAgentModel,
  agentDast, setAgentDast,
  agentDastUrl, setAgentDastUrl,
  agentConfirmLarge, setAgentConfirmLarge,
  disabled,
}) {
  return (
    <div className="space-y-3">
      <div className="space-y-2">
        <Label htmlFor="agent-path">Repository path *</Label>
        <Input
          id="agent-path"
          type="text"
          value={agentPath}
          onChange={(e) => setAgentPath(e.target.value)}
          placeholder="/path/to/repo"
          disabled={disabled}
        />
      </div>
      <div className="space-y-2">
        <Label htmlFor="agent-model">Model (optional)</Label>
        <Input
          id="agent-model"
          type="text"
          value={agentModel}
          onChange={(e) => setAgentModel(e.target.value)}
          placeholder="sonnet"
          disabled={disabled}
        />
      </div>
      <div className="flex items-center gap-2">
        <Checkbox
          id="agent-dast"
          checked={agentDast}
          onCheckedChange={setAgentDast}
          disabled={disabled}
        />
        <Label htmlFor="agent-dast" className="cursor-pointer">Enable DAST</Label>
      </div>
      {agentDast && (
        <div className="space-y-2">
          <Label htmlFor="agent-dast-url">DAST URL</Label>
          <Input
            id="agent-dast-url"
            type="url"
            value={agentDastUrl}
            onChange={(e) => setAgentDastUrl(e.target.value)}
            placeholder="https://..."
            disabled={disabled}
          />
        </div>
      )}
      <div className="flex items-center gap-2">
        <Checkbox
          id="agent-confirm-large"
          checked={agentConfirmLarge}
          onCheckedChange={setAgentConfirmLarge}
          disabled={disabled}
        />
        <Label htmlFor="agent-confirm-large" className="cursor-pointer">
          Confirm large scan (proceed over file/size limits)
        </Label>
      </div>
    </div>
  );
}

function PrReviewInputs({
  prPath, setPrPath,
  prRange, setPrRange,
  prLastN, setPrLastN,
  disabled,
}) {
  return (
    <div className="space-y-3">
      <div className="space-y-2">
        <Label htmlFor="pr-path">Repository path *</Label>
        <Input
          id="pr-path"
          type="text"
          value={prPath}
          onChange={(e) => setPrPath(e.target.value)}
          placeholder="/path/to/repo"
          disabled={disabled}
        />
      </div>
      <div className="space-y-2">
        <Label htmlFor="pr-range">Commit range (e.g. main..feature)</Label>
        <Input
          id="pr-range"
          type="text"
          value={prRange}
          onChange={(e) => setPrRange(e.target.value)}
          placeholder="main..HEAD or leave blank for last N"
          disabled={disabled}
        />
      </div>
      <div className="space-y-2">
        <Label htmlFor="pr-last-n">Or last N commits</Label>
        <Input
          id="pr-last-n"
          type="number"
          min={1}
          value={prLastN}
          onChange={(e) => setPrLastN(parseInt(e.target.value, 10) || 1)}
          disabled={disabled}
          className="w-24"
        />
      </div>
    </div>
  );
}

export function ScanInputs({ mode, disabled, urlScan, agentScan, prReview }) {
  if (mode === "url") {
    return <UrlScanInputs disabled={disabled} {...urlScan} />;
  }
  if (mode === "agent") {
    return <AgentScanInputs disabled={disabled} {...agentScan} />;
  }
  return <PrReviewInputs disabled={disabled} {...prReview} />;
}
