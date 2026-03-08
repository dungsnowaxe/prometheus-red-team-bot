import express from "express";
import { createServer as createViteServer } from "vite";
import Database from "better-sqlite3";
import path from "path";
import { fileURLToPath } from "url";
import { spawn } from "child_process";
import os from "os";
import crypto from "crypto";
import fs from "fs";
import dotenv from "dotenv";

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);
dotenv.config({ path: path.join(__dirname, ".env") });

const db = new Database("sessions.db");
const defaultSeverity = (v: string | undefined) =>
  v === "high" ? "High" : v === "medium" ? "Medium" : "Safe";

const normalizeSession = (
  session: any,
  ctx: { target_url?: string; target_name?: string; objective?: string; skill?: string },
) => {
  const normalized: any = { ...session };
  const attempts = (session.attempts || []).map((a: any, idx: number) => {
    const verdict = {
      is_vulnerable: !!a.verdict?.is_vulnerable,
      reason: a.verdict?.reason || "No reason provided",
      severity: a.verdict?.severity || "low",
      category: a.verdict?.category || "General",
      mitigation:
        a.verdict?.mitigation ||
        "Review prompts and tighten safety filters; add PII/output scanning.",
      heuristics: a.verdict?.heuristics || [],
      risk_score:
        typeof a.verdict?.risk_score === "number"
          ? a.verdict.risk_score
          : a.verdict?.is_vulnerable
            ? 80
            : 5,
      confidence: a.verdict?.confidence || "Low",
    };

    const severity = defaultSeverity(verdict.severity);

    return {
      id: a.id || `${session.session_id || "sess"}-a${idx + 1}`,
      session_id: session.session_id,
      payload: a.attempt?.payload || "",
      response: a.attempt?.target_response || "",
      objective: a.attempt?.objective || session.objective || ctx.objective || "",
      verdict,
      severity,
      created_at: a.timestamp || new Date().toISOString(),
    };
  });

  normalized.attempts = attempts;
  normalized.status = attempts.some((a: any) => a.verdict.is_vulnerable)
    ? "success"
    : "idle";
  normalized.session_id = session.session_id;
  normalized.name =
    normalized.name ||
    (ctx.objective ? `Probe: ${ctx.objective}` : `Probe: ${ctx.skill || "skill"}`);
  normalized.target =
    normalized.target || ctx.target_name || ctx.target_url || "offline";
  normalized.skill = normalized.skill || ctx.skill || "grandma";
  normalized.objective = normalized.objective || ctx.objective || "";
  normalized.model = normalized.model || "gpt-4o-mini";
  normalized.created_at = normalized.created_at || new Date().toISOString();
  return normalized;
};

// Initialize DB
db.exec(`
  CREATE TABLE IF NOT EXISTS sessions (
    id TEXT PRIMARY KEY,
    name TEXT,
    target TEXT,
    skill TEXT,
    objective TEXT,
    model TEXT,
    status TEXT,
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP
  );

  CREATE TABLE IF NOT EXISTS attempts (
    id TEXT PRIMARY KEY,
    session_id TEXT,
    payload TEXT,
    response TEXT,
    verdict TEXT,
    severity TEXT,
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY(session_id) REFERENCES sessions(id)
  );
`);

// Seed Dummy Data if empty
const sessionCount = db
  .prepare("SELECT COUNT(*) as count FROM sessions")
  .get() as { count: number };
if (sessionCount.count === 0) {
  const dummySessions = [
    {
      id: "s1",
      name: "Slack Security Audit",
      target: "Slack Bot",
      skill: "Grandma Jailbreak",
      objective: "Bypass workspace restrictions",
      model: "gemini-3-flash-preview",
      status: "success",
      created_at: "2026-03-04T10:00:00Z",
    },
    {
      id: "s2",
      name: "Local API Stress Test",
      target: "Local Instance",
      skill: "JSON Injection",
      objective: "Extract environment variables",
      model: "gemini-3-flash-preview",
      status: "success",
      created_at: "2026-03-04T14:30:00Z",
    },
    {
      id: "s4",
      name: "Local Instance 2 Diagnostics",
      target: "Local Instance 2",
      skill: "JSON Injection",
      objective: "Dump runtime config",
      model: "gemini-3-flash-preview",
      status: "success",
      created_at: "2026-03-05T09:00:00Z",
    },
    {
      id: "s3",
      name: "Production Perimeter Probe",
      target: "Production API",
      skill: "DAN (Do Anything Now)",
      objective: "Bypass PII filters",
      model: "gemini-3-flash-preview",
      status: "error",
      created_at: "2026-03-05T08:15:00Z",
    },
  ];

  const insertSession = db.prepare(
    "INSERT INTO sessions (id, name, target, skill, objective, model, status, created_at) VALUES (?, ?, ?, ?, ?, ?, ?, ?)",
  );
  const insertAttempt = db.prepare(
    "INSERT INTO attempts (id, session_id, payload, response, verdict, severity, created_at) VALUES (?, ?, ?, ?, ?, ?, ?)",
  );

  dummySessions.forEach((s) => {
    insertSession.run(
      s.id,
      s.name,
      s.target,
      s.skill,
      s.objective,
      s.model,
      s.status,
      s.created_at,
    );

    // Add 2-3 attempts per session
    for (let i = 1; i <= 2; i++) {
      const severity = i === 2 && s.id !== "s3" ? "High" : "Safe";
      const verdict = {
        is_vulnerable: severity === "High",
        reason:
          severity === "High"
            ? "Sensitive data pattern detected in output."
            : "Model refused to comply with malicious request.",
        severity: severity === "High" ? "high" : "low",
        heuristics:
          severity === "High"
            ? ["Data Leak", "Filter Bypass"]
            : ["Refusal Triggered"],
        risk_score: severity === "High" ? 85 : 12,
        confidence: "High",
        category:
          severity === "High" ? "Sensitive Data Exposure" : "Safe Response",
        mitigation:
          severity === "High"
            ? "Implement stricter output filtering and PII detection layers."
            : "No mitigation required.",
      };
      insertAttempt.run(
        `${s.id}-a${i}`,
        s.id,
        `Dummy payload for ${s.skill} attempt ${i}`,
        `Dummy response for ${s.skill} attempt ${i}. ${severity === "High" ? "Here is the internal config: {SECRET_KEY: '12345'}" : "I cannot fulfill this request."}`,
        JSON.stringify(verdict),
        severity,
        new Date(new Date(s.created_at).getTime() + i * 60000).toISOString(),
      );
    }
  });
}

async function startServer() {
  const app = express();
  const PORT = 3000;

  app.use(express.json());

  const CORE_DIR = path.join(__dirname, "..", "core");
  const defaultPy = path.join(CORE_DIR, ".venv", "bin", "python3");
  const PY_BIN =
    process.env.PROMPTHEUS_PYTHON ||
    (fs.existsSync(defaultPy) ? defaultPy : "python3");

  const runPromptheus = async (opts: {
    target_url?: string;
    target_name?: string;
    objective: string;
    skill?: string;
    attempts?: number;
    offline?: boolean;
    api_key?: string;
    base_url?: string;
  }) => {
    const args = [
      "-m",
      "promptheus.interfaces.cli",
      "attack",
      "--objective",
      opts.objective,
      "--skill",
      opts.skill || "grandma",
      "--attempts",
      String(opts.attempts || 1),
      "--json-output",
    ];
    if (opts.offline || !opts.target_url) {
      args.push("--offline");
    } else {
      args.push("--target-url", opts.target_url);
    }

    return new Promise<any>((resolve, reject) => {
      const env: NodeJS.ProcessEnv = {
        ...process.env,
        PYTHONPATH: CORE_DIR,
      };
      const effectiveKey = opts.api_key || process.env.OPENAI_API_KEY;
      const effectiveBase = opts.base_url || process.env.OPENAI_BASE_URL;
      if (effectiveKey) env.OPENAI_API_KEY = effectiveKey;
      if (effectiveBase) env.OPENAI_BASE_URL = effectiveBase;

      const proc = spawn(PY_BIN, args, {
        cwd: CORE_DIR,
        env,
      });
      let stdout = "";
      let stderr = "";
      proc.stdout.on("data", (d) => (stdout += d.toString()));
      proc.stderr.on("data", (d) => (stderr += d.toString()));
      proc.on("close", (code) => {
        if (code !== 0) return reject(new Error(stderr || stdout));
        const text = stdout.trim();

        const tryParse = (s: string) => {
          try {
            return JSON.parse(s);
          } catch {
            return null;
          }
        };

        const extractBalanced = (blob: string) => {
          const candidates: string[] = [];
          let depth = 0;
          let start = -1;
          for (let i = 0; i < blob.length; i++) {
            const ch = blob[i];
            if (ch === "{") {
              if (depth === 0) start = i;
              depth += 1;
            } else if (ch === "}") {
              if (depth > 0) depth -= 1;
              if (depth === 0 && start !== -1) {
                candidates.push(blob.slice(start, i + 1));
                start = -1;
              }
            }
          }
          // prefer larger blobs that contain useful keys
          candidates.sort((a, b) => b.length - a.length);
          for (const cand of candidates) {
            const parsed = tryParse(cand);
            if (parsed && (parsed.session_id || parsed.attempts)) return parsed;
          }
          return null;
        };

        // 1) whole buffer
        const whole = tryParse(text);
        if (whole) return resolve(whole);

        // 2) line by line (bottom-up)
        const lines = text.split(/\r?\n/).map((l) => l.trim()).filter(Boolean);
        for (let i = lines.length - 1; i >= 0; i--) {
          const parsed = tryParse(lines[i]);
          if (parsed) return resolve(parsed);
        }

        // 3) extract any balanced JSON object blobs (handles colored/log-prefixed output)
        const balanced = extractBalanced(text);
        if (balanced) return resolve(balanced);

        console.error("[runPromptheus] parse failure", { stdout: text, stderr });
        // Fallback: wrap raw output so UI still shows something instead of 500
        return resolve({
          session_id: crypto.randomUUID(),
          target: opts.target_name || opts.target_url || "unknown",
          objective: opts.objective,
          attempts: [
            {
              attempt: {
                skill: opts.skill || "grandma",
                objective: opts.objective,
                payload: "(unparsed output)",
                target_response: text,
              },
              verdict: {
                is_vulnerable: false,
                reason: "Failed to parse session JSON from core output",
                severity: "low",
              },
              severity: "Safe",
              timestamp: new Date().toISOString(),
            },
          ],
        });
      });
    });
  };

  // API Routes
  app.get("/api/sessions", (req, res) => {
    const sessions = db
      .prepare("SELECT * FROM sessions ORDER BY created_at DESC")
      .all();
    res.json(sessions);
  });

  app.get("/api/sessions/:id", (req, res) => {
    const session = db
      .prepare("SELECT * FROM sessions WHERE id = ?")
      .get(req.params.id);
    if (!session) return res.status(404).json({ error: "Session not found" });

    const attemptsRaw = db
      .prepare(
        "SELECT * FROM attempts WHERE session_id = ? ORDER BY created_at ASC",
      )
      .all(req.params.id);

    const attempts = attemptsRaw.map((a: any) => {
      let verdict: any = {};
      try {
        verdict = a.verdict ? JSON.parse(a.verdict) : {};
      } catch (err) {
        verdict = {};
      }
      return { ...a, verdict };
    });

    res.json({ ...session, attempts });
  });

  app.post("/api/sessions", (req, res) => {
    const { id, name, target, skill, objective, model } = req.body;
    db.prepare(
      "INSERT INTO sessions (id, name, target, skill, objective, model, status) VALUES (?, ?, ?, ?, ?, ?, ?)",
    ).run(id, name, target, skill, objective, model, "running");
    res.json({ success: true });
  });

  // Launch an attack via Python core and persist results
  app.post("/api/attack", async (req, res) => {
    const {
      target_url,
      target_name,
      objective,
      objectives,
      skill = "grandma",
      attempts = 1,
      offline = false,
      api_key,
      base_url,
      session_name,
    } = req.body;
    const cleanSessionName =
      typeof session_name === "string" && session_name.trim().length > 0
        ? session_name.trim()
        : undefined;
    const allowClientKey = process.env.ALLOW_CLIENT_API_KEY === "true";
    const sessionId = crypto.randomUUID();
    try {
      const objectivesList: string[] =
        Array.isArray(objectives) && objectives.length > 0
          ? objectives
          : [objective];

      const collected: any[] = [];
      for (const obj of objectivesList) {
        try {
          const sess = await runPromptheus({
            target_url,
            target_name,
            objective: obj,
            skill,
            attempts,
            offline,
            api_key: allowClientKey ? api_key : undefined,
            base_url: allowClientKey ? base_url : undefined,
          });
          collected.push(sess);
        } catch (err: any) {
          // Record a stub session for this objective so the batch still returns
          collected.push({
            session_id: crypto.randomUUID(),
            target: target_name || target_url || "unknown",
            objective: obj,
            attempts: [
              {
                attempt: {
                  skill,
                  objective: obj,
                  payload: "(request failed)",
                  target_response: err?.message || "Request failed",
                },
                verdict: {
                  is_vulnerable: false,
                  reason: err?.message || "Request failed",
                  severity: "low",
                },
                timestamp: new Date().toISOString(),
              },
            ],
          });
        }
      }

      // Combine into a single aggregated session
      const aggId = collected[0]?.session_id || sessionId;
      const aggAttempts = collected.flatMap((s, sIdx) =>
        (s.attempts || []).map((a: any, i: number) => ({
          ...a,
          objective: a.attempt?.objective || objectivesList[sIdx] || a.objective || "",
          id: `${aggId}-o${sIdx + 1}-a${i + 1}`,
        })),
      );
      // ensure at least one attempt per objective
      const expectedPerObjective = Math.max(1, attempts);
      objectivesList.forEach((objText, idx) => {
        const existing = aggAttempts.filter((a) => (a as any).objective === objText);
        for (let i = existing.length; i < expectedPerObjective; i++) {
          aggAttempts.push({
            id: `${aggId}-o${idx + 1}-stub${i + 1}`,
            attempt: {
              skill,
              objective: objText,
              payload: "(no attempt returned)",
              target_response: "",
            },
            objective: objText,
            verdict: {
              is_vulnerable: false,
              reason: "No attempt returned",
              severity: "low",
            },
            timestamp: new Date().toISOString(),
          });
        }
      });
      const combinedObjective = objectivesList.join(" | ");
      const agg = normalizeSession(
        {
          session_id: aggId,
          attempts: aggAttempts,
          target: collected[0]?.target,
          objective: combinedObjective,
          skill: skill,
          model: collected[0]?.model,
          created_at: collected[0]?.created_at,
          name: cleanSessionName || `Batch (${objectivesList.length}) • ${skill}`,
        },
        { target_url, target_name, objective: combinedObjective, skill },
      );
      if (cleanSessionName) {
        agg.name = cleanSessionName;
      }

      db.prepare(
        "INSERT OR REPLACE INTO sessions (id, name, target, skill, objective, model, status, created_at) VALUES (?, ?, ?, ?, ?, ?, ?, ?)",
      ).run(
        agg.session_id,
        agg.name,
        agg.target,
        agg.skill,
        agg.objective,
        agg.model,
        agg.status,
        agg.created_at,
      );

      const insertAttempt = db.prepare(
        "INSERT OR REPLACE INTO attempts (id, session_id, payload, response, verdict, severity, created_at) VALUES (?, ?, ?, ?, ?, ?, ?)",
      );
      (agg.attempts || []).forEach((a: any) => {
        insertAttempt.run(
          a.id,
          agg.session_id,
          a.payload || "",
          a.response || "",
          JSON.stringify(a.verdict || {}),
          a.severity,
          a.created_at || new Date().toISOString(),
        );
      });

      res.json(agg);
    } catch (err: any) {
      console.error("Attack failed", err);
      res.status(500).json({ error: err.message || "Attack failed" });
    }
  });

  app.post("/api/attempts", (req, res) => {
    const { id, session_id, payload, response, verdict, severity } = req.body;
    db.prepare(
      "INSERT INTO attempts (id, session_id, payload, response, verdict, severity) VALUES (?, ?, ?, ?, ?, ?)",
    ).run(id, session_id, payload, response, JSON.stringify(verdict), severity);
    res.json({ success: true });
  });

  app.patch("/api/sessions/:id", (req, res) => {
    const { status } = req.body;
    db.prepare("UPDATE sessions SET status = ? WHERE id = ?").run(
      status,
      req.params.id,
    );
    res.json({ success: true });
  });

  app.delete("/api/sessions/all", (req, res) => {
    db.prepare("DELETE FROM attempts").run();
    db.prepare("DELETE FROM sessions").run();
    res.json({ success: true });
  });

  app.delete("/api/sessions/:id", (req, res) => {
    db.prepare("DELETE FROM attempts WHERE session_id = ?").run(req.params.id);
    db.prepare("DELETE FROM sessions WHERE id = ?").run(req.params.id);
    res.json({ success: true });
  });

  // Vite middleware for development
  if (process.env.NODE_ENV !== "production") {
    const vite = await createViteServer({
      server: { middlewareMode: true },
      appType: "spa",
    });
    app.use(vite.middlewares);
  } else {
    app.use(express.static(path.join(__dirname, "dist")));
    app.get("*", (req, res) => {
      res.sendFile(path.join(__dirname, "dist", "index.html"));
    });
  }

  app.listen(PORT, "0.0.0.0", () => {
    console.log(`Server running on http://localhost:${PORT}`);
  });
}

startServer();
