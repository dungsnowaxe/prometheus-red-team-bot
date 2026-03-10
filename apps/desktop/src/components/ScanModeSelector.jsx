import { RadioGroup, RadioGroupItem } from "@/components/ui/radio-group";
import { Label } from "@/components/ui/label";

const MODES = [
  { value: "url", label: "URL Scan" },
  { value: "agent", label: "Agent Scan" },
  { value: "pr", label: "PR Review" },
];

export function ScanModeSelector({ mode, onModeChange, disabled }) {
  return (
    <RadioGroup
      value={mode}
      onValueChange={onModeChange}
      disabled={disabled}
      className="flex flex-row gap-4"
    >
      {MODES.map(({ value, label }) => (
        <div key={value} className="flex items-center gap-2">
          <RadioGroupItem value={value} id={`mode-${value}`} />
          <Label htmlFor={`mode-${value}`} className="cursor-pointer">
            {label}
          </Label>
        </div>
      ))}
    </RadioGroup>
  );
}
