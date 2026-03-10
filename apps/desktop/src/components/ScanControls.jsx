import { Button } from "@/components/ui/button";
import { Loader2 } from "lucide-react";

export function ScanControls({ running, canRun, runLabel, onRun, onCancel }) {
  return (
    <div className="flex items-center gap-2">
      <Button onClick={onRun} disabled={running || !canRun} size="lg">
        {running ? (
          <>
            <Loader2 className="animate-spin" />
            {runLabel ? `Running ${runLabel}...` : "Running..."}
          </>
        ) : (
          "Run Scan"
        )}
      </Button>
      {running && (
        <Button variant="destructive" onClick={onCancel} size="lg">
          Cancel
        </Button>
      )}
    </div>
  );
}
