import {
  Table, TableHeader, TableBody, TableRow, TableHead, TableCell,
} from "@/components/ui/table";
import { Badge } from "@/components/ui/badge";

function severityVariant(severity) {
  if (!severity) return "secondary";
  const s = severity.toLowerCase();
  if (s === "critical" || s === "high") return "destructive";
  if (s === "medium") return "outline";
  return "secondary";
}

function IssueTable({ results }) {
  return (
    <Table>
      <TableHeader>
        <TableRow>
          <TableHead>Title</TableHead>
          <TableHead>Severity</TableHead>
          <TableHead>File</TableHead>
          <TableHead>Line</TableHead>
          <TableHead>Description</TableHead>
        </TableRow>
      </TableHeader>
      <TableBody>
        {results.map((r, i) => (
          <TableRow key={i}>
            <TableCell className="font-medium">{r.title ?? "-"}</TableCell>
            <TableCell>
              <Badge variant={severityVariant(r.severity)}>{r.severity ?? "-"}</Badge>
            </TableCell>
            <TableCell className="max-w-40 truncate text-muted-foreground">{r.file_path ?? "-"}</TableCell>
            <TableCell className="text-muted-foreground">{r.line_number ?? "-"}</TableCell>
            <TableCell className="max-w-64 truncate">{r.description ?? "-"}</TableCell>
          </TableRow>
        ))}
      </TableBody>
    </Table>
  );
}

function VulnerabilityTable({ results }) {
  return (
    <Table>
      <TableHeader>
        <TableRow>
          <TableHead>Payload</TableHead>
          <TableHead>Verdict</TableHead>
          <TableHead>Severity</TableHead>
          <TableHead>Reasoning</TableHead>
        </TableRow>
      </TableHeader>
      <TableBody>
        {results.map((r, i) => (
          <TableRow key={i}>
            <TableCell className="font-medium">{r.name}</TableCell>
            <TableCell>
              <Badge variant={r.vulnerable ? "destructive" : "secondary"}>
                {r.vulnerable ? "Vulnerable" : "Safe"}
              </Badge>
            </TableCell>
            <TableCell>
              <Badge variant={severityVariant(r.severity)}>{r.severity}</Badge>
            </TableCell>
            <TableCell className="max-w-64 truncate">{r.reasoning || "-"}</TableCell>
          </TableRow>
        ))}
      </TableBody>
    </Table>
  );
}

export function ResultsTable({ result }) {
  if (!result) return null;

  const isIssue = (r) => r && (r.title != null || r.severity != null);

  return (
    <div className="space-y-3">
      {result.code !== 0 && (
        <p className="text-sm text-destructive">
          Exit code {result.code}: {result.stderr?.slice(0, 300)}
        </p>
      )}
      {result.results && result.results.length > 0 && (
        isIssue(result.results[0])
          ? <IssueTable results={result.results} />
          : <VulnerabilityTable results={result.results} />
      )}
      {result.results && result.results.length === 0 && result.code === 0 && (
        <p className="text-sm text-muted-foreground">No findings.</p>
      )}
    </div>
  );
}
