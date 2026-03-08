import React, { useState, useEffect, useRef, useMemo } from "react";
import {
  Play,
  Square,
  Search,
  Filter,
  Copy,
  Download,
  ChevronRight,
  ChevronLeft,
  AlertTriangle,
  ShieldCheck,
  ShieldAlert,
  Terminal,
  Settings,
  History,
  Target as TargetIcon,
  Zap,
  MoreVertical,
  ExternalLink,
  CheckCircle2,
  XCircle,
  Trash2,
} from "lucide-react";
import { motion, AnimatePresence } from "motion/react";
import { Session, Attempt, Skill, Target, Verdict } from "./types";
import { SKILLS, TARGETS, OBJECTIVES } from "./constants";

export default function App() {
  const [view, setView] = useState<"dashboard" | "settings" | "targets">(
    "dashboard",
  );
  const [sessions, setSessions] = useState<Session[]>([]);
  const [activeSession, setActiveSession] = useState<Session | null>(null);
  const [selectedAttempt, setSelectedAttempt] = useState<Attempt | null>(null);
  const [isSidebarOpen, setIsSidebarOpen] = useState(true);
  const [isAttacking, setIsAttacking] = useState(false);
  const [searchQuery, setSearchQuery] = useState("");
  const [skillFilter, setSkillFilter] = useState<string | null>(null);

  // Form State
  const [objective, setObjective] = useState("");
  const [selectedTarget, setSelectedTarget] = useState<Target>(TARGETS[0]);
  const [targetUrl, setTargetUrl] = useState<string>(TARGETS[0].config.url || "");
  const [selectedSkill, setSelectedSkill] = useState<Skill>(SKILLS[1] || SKILLS[0]);
  const [attemptsCount, setAttemptsCount] = useState(3);
  const [isDryRun, setIsDryRun] = useState(false);
  const [apiKey, setApiKey] = useState("");
  const [baseUrl, setBaseUrl] = useState("");
  const [allowClientKey, setAllowClientKey] = useState(false);
  const [sessionName, setSessionName] = useState("");
  const [selectedObjectiveIds, setSelectedObjectiveIds] = useState<string[]>([]);
  const [errorMessage, setErrorMessage] = useState<string | null>(null);
  const [successMessage, setSuccessMessage] = useState<string | null>(null);

  const timelineEndRef = useRef<HTMLDivElement>(null);
  const groupedAttempts = useMemo(() => {
    if (!activeSession?.attempts) return [];
    const groups: Record<string, Attempt[]> = {};
    activeSession.attempts.forEach((a) => {
      const key = (a as any).objective || "Unspecified objective";
      groups[key] = groups[key] || [];
      groups[key].push(a);
    });
    return Object.entries(groups).map(([objective, attempts]) => ({
      objective,
      attempts,
    }));
  }, [activeSession]);

  useEffect(() => {
    fetchSessions();
    const interval = setInterval(fetchSessions, 8000);
    return () => clearInterval(interval);
  }, []);

  // load saved creds (local only; not persisted to server)
  useEffect(() => {
    const savedKey = localStorage.getItem("promptheus_api_key");
    const savedBase = localStorage.getItem("promptheus_base_url");
    const savedAllow = localStorage.getItem("promptheus_allow_client_key");
    if (savedKey) setApiKey(savedKey);
    if (savedBase) setBaseUrl(savedBase);
    if (savedAllow) setAllowClientKey(savedAllow === "true");
  }, []);

  useEffect(() => {
    if (activeSession?.attempts) {
      timelineEndRef.current?.scrollIntoView({ behavior: "smooth" });
    }
  }, [activeSession?.attempts]);

  // keep editable target URL in sync when switching targets
  useEffect(() => {
    setTargetUrl(selectedTarget.config.url || "");
    setSelectedObjectiveIds([]); // reset queued objectives when target changes
  }, [selectedTarget]);

  const fetchSessions = async () => {
    try {
      const res = await fetch("/api/sessions");
      const data = await res.json();
      setSessions(data);
    } catch (err) {
      console.error("Failed to fetch sessions", err);
    }
  };

  const fetchSessionDetail = async (id: string) => {
    try {
      const res = await fetch(`/api/sessions/${id}`);
      const data = await res.json();

      // Align selected target/skill with the session we just loaded
      if (data?.target) {
        const matchTarget = TARGETS.find(
          (t) => t.name.toLowerCase() === String(data.target).toLowerCase(),
        );
        if (matchTarget) {
          setSelectedTarget(matchTarget);
          setTargetUrl(matchTarget.config.url || "");
        }
      }
      if (data?.skill) {
        const matchSkill =
          SKILLS.find(
            (s) => s.id === data.skill || s.name.toLowerCase() === String(data.skill).toLowerCase(),
          ) || SKILLS[0];
        setSelectedSkill(matchSkill);
      }

      setActiveSession(data);
      if (data.attempts?.length > 0) {
        setSelectedAttempt(data.attempts[data.attempts.length - 1]);
      }
    } catch (err) {
      console.error("Failed to fetch session detail", err);
    }
  };

  const deleteHistory = async () => {
    if (
      !confirm(
        "Are you sure you want to clear all session history? This action cannot be undone.",
      )
    )
      return;

    try {
      // In a real app, we'd have a DELETE /api/sessions endpoint that clears all
      // For now, we'll delete them one by one or just clear the local state if the backend doesn't support bulk delete
      // But I added app.delete("/api/sessions/:id") in server.ts, so I can use that for individual or implement a bulk one

      // Let's assume we want to clear ALL. I'll add a bulk delete route to server.ts in a moment if needed,
      // but for now let's just clear the state and call the individual deletes for simplicity or just a bulk one.

      const response = await fetch("/api/sessions/all", { method: "DELETE" });
      if (response.ok) {
        setSessions([]);
        setActiveSession(null);
        setSelectedAttempt(null);
      }
    } catch (err) {
      console.error("Failed to delete history", err);
    }
  };

  const deleteSession = async (id: string) => {
    try {
      const response = await fetch(`/api/sessions/${id}`, { method: "DELETE" });
      if (response.ok) {
        setSessions((prev) => prev.filter((s) => s.id !== id));
        if (activeSession?.id === id) {
          setActiveSession(null);
          setSelectedAttempt(null);
        }
      }
    } catch (err) {
      console.error("Failed to delete session", err);
    }
  };

  const executeAttack = async (
    objectiveTexts: string[],
    attemptsOverride: number,
    sessionNameOverride?: string,
  ): Promise<Session> => {
    const res = await fetch("/api/attack", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({
        target_url: isDryRun ? null : (targetUrl?.trim() || null),
        target_name: selectedTarget.name,
        objective: objectiveTexts[0],
        objectives: objectiveTexts,
        skill: selectedSkill.id,
        attempts: attemptsOverride,
        offline: isDryRun || !(targetUrl && targetUrl.trim()),
        session_name: sessionNameOverride || undefined,
        api_key: allowClientKey ? apiKey || undefined : undefined,
        base_url: allowClientKey ? baseUrl || undefined : undefined,
      }),
    });
    if (!res.ok) throw new Error(await res.text());
    return res.json();
  };

  const launchAttack = async () => {
    if (isAttacking) return;
    setErrorMessage(null);
    setSuccessMessage(null);

    if (selectedObjectiveIds.length === 0 && !objective.trim()) {
      setErrorMessage("Please enter an objective or select at least one preset.");
      return;
    }

    const cleanSessionName = sessionName.trim();
    const objectivesToRun =
      selectedObjectiveIds.length > 0
        ? OBJECTIVES.filter((o) => selectedObjectiveIds.includes(o.id))
        : [{ id: "custom", label: "Custom", text: objective }];
    const effectiveAttempts = attemptsCount;

    setIsAttacking(true);
    setActiveSession(null);
    setSelectedAttempt(null);
    setIsSidebarOpen(false);

    try {
      const session = await executeAttack(
        objectivesToRun.map((o) => o.text),
        effectiveAttempts,
        cleanSessionName,
      );

      const sessionWithName =
        cleanSessionName && cleanSessionName.length > 0
          ? { ...session, name: cleanSessionName }
          : session;
      setActiveSession(sessionWithName);
      if (session.attempts?.length) {
        setSelectedAttempt(session.attempts[session.attempts.length - 1]);
      }
      setIsSidebarOpen(true);
      setSuccessMessage(
        objectivesToRun.length > 1
          ? `Completed ${objectivesToRun.length} objectives in one batch`
          : "Attack completed",
      );
      fetchSessions();
    } catch (err) {
      console.error("Attack failed", err);
      setErrorMessage(err instanceof Error ? err.message : "Attack failed");
    } finally {
      setIsAttacking(false);
    }
  };

  return (
    <div className="flex h-screen overflow-hidden">
      {/* Left Rail: Targets & Skills */}
      <aside className="w-64 glass-panel flex flex-col z-20">
        <div className="p-4 border-b border-white/5 flex items-center gap-2">
          <div className="w-8 h-8 bg-cyan-accent rounded flex items-center justify-center text-charcoal font-bold">
            P
          </div>
          <h1 className="font-bold tracking-tight text-lg">PROMPTHEUS</h1>
        </div>

        <div className="flex-1 overflow-y-auto p-4 space-y-6">
          {/* Targets */}
          <section>
            <div className="flex items-center justify-between mb-3">
              <h2 className="text-xs font-semibold uppercase tracking-widest text-white/40">
                Targets
              </h2>
              <TargetIcon size={14} className="text-white/40" />
            </div>
            <div className="space-y-1">
              {TARGETS.map((t) => (
                <button
                  key={t.id}
                  onClick={() => {
                    setSelectedTarget(t);
                    setView("targets");
                  }}
                  className={`w-full text-left px-3 py-2 rounded-md text-sm transition-all flex items-center gap-2 ${selectedTarget.id === t.id && view === "targets" ? "bg-cyan-accent/10 text-cyan-accent border border-cyan-accent/20" : "text-white/60 hover:bg-white/5"}`}
                >
                  <div
                    className={`w-1.5 h-1.5 rounded-full ${selectedTarget.id === t.id && view === "targets" ? "bg-cyan-accent" : "bg-white/20"}`}
                  />
                  {t.name}
                </button>
              ))}
            </div>
          </section>

          {/* Skills */}
          <section>
            <div className="flex items-center justify-between mb-3">
              <h2 className="text-xs font-semibold uppercase tracking-widest text-white/40">
                Skills
              </h2>
              <Zap size={14} className="text-white/40" />
            </div>
            <div className="space-y-1">
              {SKILLS.map((s) => (
                <button
                  key={s.id}
                  onClick={() => setSelectedSkill(s)}
                  className={`w-full text-left px-3 py-2 rounded-md text-sm transition-all group ${selectedSkill.id === s.id ? "bg-amber-accent/10 text-amber-accent border border-amber-accent/20" : "text-white/60 hover:bg-white/5"}`}
                >
                  <div className="flex items-center justify-between">
                    <span>{s.name}</span>
                    <div className="flex gap-1">
                      {(s.tags || []).slice(0, 1).map((tag, idx) => (
                        <span
                          key={`${s.id}-tag-${idx}`}
                          className="text-[10px] px-1 bg-white/5 rounded text-white/40 uppercase"
                        >
                          {tag}
                        </span>
                      ))}
                    </div>
                  </div>
                </button>
              ))}
            </div>
          </section>

          {/* History */}
          <section>
            <div className="flex items-center justify-between mb-3">
              <h2 className="text-xs font-semibold uppercase tracking-widest text-white/40">
                History
              </h2>
              <History size={14} className="text-white/40" />
            </div>
            <div className="space-y-1">
              {(sessions || []).map((s) => {
                const title =
                  (s.name && s.name.trim()) ||
                  (s.objective && s.objective.split("|")[0].trim()) ||
                  s.id;
                const subtitle =
                  s.name && s.name.trim() ? s.objective || "" : s.objective || "";
                return (
                  <div key={s.id} className="group relative">
                    <button
                      onClick={() => {
                        fetchSessionDetail(s.id);
                        setView("dashboard");
                      }}
                      className={`w-full text-left px-3 py-2 rounded-md text-xs transition-all truncate pr-8 ${activeSession?.id === s.id ? "bg-white/10 text-white" : "text-white/40 hover:bg-white/5"}`}
                    >
                      <div className="flex flex-col truncate">
                        <span className="truncate">{title}</span>
                        {subtitle && (
                          <span className="text-[10px] text-white/30 truncate">
                            {subtitle}
                          </span>
                        )}
                      </div>
                    </button>
                    <button
                      onClick={(e) => {
                        e.stopPropagation();
                        if (confirm("Delete this session?")) deleteSession(s.id);
                      }}
                      className="absolute right-2 top-1/2 -translate-y-1/2 p-1 text-white/0 group-hover:text-white/40 hover:text-error-red transition-all"
                    >
                      <Trash2 size={12} />
                    </button>
                  </div>
                );
              })}
            </div>
          </section>
        </div>

        <div className="p-4 border-t border-white/5">
          <button
            onClick={() => setView("dashboard")}
            className={`w-full flex items-center gap-2 text-xs mb-2 transition-colors ${view === "dashboard" ? "text-cyan-accent" : "text-white/40 hover:text-white"}`}
          >
            <Terminal size={14} />
            Dashboard
          </button>
          <button
            onClick={() => setView("settings")}
            className={`w-full flex items-center gap-2 text-xs transition-colors ${view === "settings" ? "text-cyan-accent" : "text-white/40 hover:text-white"}`}
          >
            <Settings size={14} />
            Settings & API Keys
          </button>
        </div>
      </aside>

      {/* Main Canvas */}
      <main className="flex-1 flex flex-col min-w-0 bg-charcoal/50">
        {view === "dashboard" ? (
          <div className="flex-1 flex flex-col min-h-0">
            {/* Attack Setup Panel */}
            <div className="p-6 border-b border-white/5 bg-charcoal/30">
              <div className="max-w-5xl mx-auto grid grid-cols-1 lg:grid-cols-4 gap-6">
                <div className="lg:col-span-2 space-y-4">
                  <div className="flex items-center justify-between">
                    <h3 className="text-xs font-semibold uppercase tracking-widest text-white/40">
                      Attack Objective
                    </h3>
                    <div className="flex items-center gap-2">
                      <span className="text-[10px] text-white/20">Target:</span>
                      <span className="text-[10px] font-bold text-cyan-accent">
                        {selectedTarget.name}
                      </span>
                    </div>
                  </div>
                  <input
                    value={sessionName}
                    onChange={(e) => setSessionName(e.target.value)}
                    placeholder="Optional session name (will appear in History)"
                    className="w-full bg-charcoal/50 border border-white/10 rounded-lg px-3 py-2 text-xs text-white placeholder:text-white/20 focus:border-cyan-accent/60 focus:ring-1 focus:ring-cyan-accent/40 outline-none"
                  />
                  <textarea
                    value={objective}
                    onChange={(e) => setObjective(e.target.value)}
                    placeholder="Describe what you want to extract or achieve..."
                    className="w-full h-24 bg-charcoal/50 border border-white/10 rounded-xl p-4 text-sm text-white placeholder:text-white/20 focus:border-cyan-accent/50 focus:ring-1 focus:ring-cyan-accent/50 outline-none transition-all resize-none"
                  />
                  <div className="flex flex-wrap gap-2">
                    {(OBJECTIVES || [])
                      .filter((o) => !o.skills || o.skills.includes(selectedSkill.id))
                      .map((o) => (
                        <button
                          key={o.id}
                          onClick={() => {
                            setObjective(o.text);
                            setSelectedObjectiveIds((prev) =>
                              prev.includes(o.id)
                                ? prev.filter((id) => id !== o.id)
                                : [...prev, o.id],
                            );
                          }}
                          className={`px-3 py-1 rounded-full border text-[11px] transition-colors ${
                            selectedObjectiveIds.includes(o.id)
                              ? "border-cyan-accent/60 bg-cyan-accent/10 text-cyan-accent"
                              : "border-white/10 bg-white/5 text-white/70 hover:border-cyan-accent/40 hover:text-cyan-accent"
                          }`}
                          title={o.text}
                        >
                          {o.label}
                        </button>
                      ))}
                  </div>
                  {selectedObjectiveIds.length > 0 && (
                    <p className="text-[11px] text-cyan-accent">
                      {selectedObjectiveIds.length} objectives queued — will be batched into one request (attempts = {attemptsCount}).
                    </p>
                  )}
                </div>

                <div className="space-y-4">
                  <h3 className="text-xs font-semibold uppercase tracking-widest text-white/40">
                    Configuration
                  </h3>
                  <div className="space-y-3">
                    <div className="flex items-center justify-between px-3 py-2 bg-white/5 rounded-lg border border-white/5">
                      <span className="text-xs text-white/60">Dry Run</span>
                      <button
                        onClick={() => setIsDryRun(!isDryRun)}
                        className={`w-8 h-4 rounded-full transition-colors relative ${isDryRun ? "bg-cyan-accent" : "bg-white/10"}`}
                      >
                        <div
                          className={`absolute top-0.5 w-3 h-3 bg-white rounded-full transition-all ${isDryRun ? "left-4.5" : "left-0.5"}`}
                        />
                      </button>
                    </div>
                    <div className="flex items-center justify-between px-3 py-2 bg-white/5 rounded-lg border border-white/5">
                      <span className="text-xs text-white/60">Attempts</span>
                      <div className="flex items-center gap-3">
                        <button
                          onClick={() =>
                            setAttemptsCount(Math.max(1, attemptsCount - 1))
                          }
                          className="text-white/40 hover:text-white"
                        >
                          -
                        </button>
                        <span className="text-xs font-bold text-cyan-accent w-4 text-center">
                          {attemptsCount}
                        </span>
                        <button
                          onClick={() =>
                            setAttemptsCount(Math.min(10, attemptsCount + 1))
                          }
                          className="text-white/40 hover:text-white"
                        >
                          +
                        </button>
                      </div>
                    </div>
                    <div className="space-y-1">
                      <label className="text-[10px] font-semibold text-white/40 uppercase">
                        Target URL
                      </label>
                      <input
                        value={targetUrl}
                        onChange={(e) => setTargetUrl(e.target.value)}
                        placeholder="https://your-endpoint/chat"
                        className="w-full bg-charcoal/50 border border-white/10 rounded-lg px-3 py-2 text-xs text-white placeholder:text-white/20 focus:border-cyan-accent/60 focus:ring-1 focus:ring-cyan-accent/40 outline-none"
                      />
                      <p className="text-[10px] text-white/30">
                        Leave empty or turn on Dry Run to stay offline.
                      </p>
                    </div>
                  </div>
                </div>

                <div className="flex flex-col justify-end">
                  <button
                    onClick={launchAttack}
                    disabled={
                      isAttacking ||
                      (!objective.trim() && selectedObjectiveIds.length === 0)
                    }
                    className={`w-full py-4 rounded-xl font-bold text-sm flex items-center justify-center gap-2 transition-all ${
                      isAttacking
                        ? "bg-white/5 text-white/40 cursor-not-allowed"
                        : "bg-cyan-accent text-charcoal hover:scale-[1.02] active:scale-[0.98] cyan-glow"
                    }`}
                  >
                    {isAttacking ? (
                      <>
                        <div className="w-4 h-4 border-2 border-charcoal/20 border-t-charcoal rounded-full animate-spin" />
                        Running...
                      </>
                    ) : (
                      <>
                        <Play size={18} fill="currentColor" />
                        Launch Attack
                      </>
                    )}
                  </button>
                </div>
              </div>
            </div>

            {/* Session Timeline */}
            <div className="flex-1 overflow-y-auto p-6">
              <div className="max-w-5xl mx-auto space-y-6">
                {activeSession ? (
                  <div className="space-y-4">
                    <div className="flex items-center justify-between">
                      <div className="flex items-center gap-3">
                        <h2 className="text-lg font-bold text-white">
                          {activeSession.name}
                        </h2>
                        {groupedAttempts.length > 1 && (
                          <span className="px-2 py-0.5 rounded text-[10px] font-bold uppercase bg-white/10 text-white/70">
                            {groupedAttempts.length} objectives
                          </span>
                        )}
                        <span
                          className={`px-2 py-0.5 rounded text-[10px] font-bold uppercase ${
                            activeSession.status === "running"
                              ? "bg-cyan-accent/20 text-cyan-accent animate-pulse"
                              : "bg-success-green/20 text-success-green"
                          }`}
                        >
                          {activeSession.status}
                        </span>
                      </div>
                      <p className="text-xs text-white/30">
                        {new Date(
                          activeSession.created_at || Date.now(),
                        ).toLocaleString()}
                      </p>
                    </div>

                    <div className="space-y-6">
                      {groupedAttempts.map((group, gIdx) => (
                        <div key={`group-${gIdx}`} className="space-y-3">
                          <div className="flex items-center justify-between text-xs text-white/50">
                            <span className="font-semibold uppercase tracking-wide">
                              Objective: {group.objective}
                            </span>
                            <span>{group.attempts.length} attempt(s)</span>
                          </div>
                          {group.attempts.map((attempt, idx) => (
                          <motion.div
                            initial={{ opacity: 0, y: 20 }}
                            animate={{ opacity: 1, y: 0 }}
                          key={attempt.id}
                            onClick={() => {
                              setSelectedAttempt(attempt);
                              setIsSidebarOpen(true);
                            }}
                            className={`glass-panel p-5 rounded-2xl cursor-pointer transition-all border ${
                            selectedAttempt?.id === attempt.id
                              ? "border-cyan-accent/50 ring-1 ring-cyan-accent/20"
                              : "border-white/5 hover:border-white/10"
                          }`}
                        >
                          <div className="flex items-start justify-between gap-4">
                            <div className="flex-1 space-y-4">
                              <div className="flex items-center gap-3">
                                <span className="text-[10px] font-mono text-white/20">
                                  #{idx + 1}
                                </span>
                                <div
                                  className={`px-2 py-0.5 rounded text-[10px] font-bold uppercase ${
                                    attempt.verdict.is_vulnerable
                                      ? "bg-error-red/20 text-error-red"
                                      : "bg-success-green/20 text-success-green"
                                  }`}
                                >
                                  {attempt.verdict.is_vulnerable
                                    ? "Vulnerable"
                                    : "Secure"}
                                </div>
                                <span className="text-[10px] text-white/30">
                                  {attempt.verdict.category || "General"}
                                </span>
                              </div>

                              <div className="grid grid-cols-1 md:grid-cols-2 gap-6">
                                <div className="space-y-2">
                                  <label className="text-[10px] font-semibold text-white/20 uppercase tracking-wider">
                                    Payload
                                  </label>
                                  <p className="text-xs text-white/80 font-mono bg-charcoal/30 p-2 rounded border border-white/5 whitespace-pre-wrap">
                                    {attempt.payload}
                                  </p>
                                </div>
                                <div className="space-y-2">
                                  <label className="text-[10px] font-semibold text-white/20 uppercase tracking-wider">
                                    Response
                                  </label>
                                  <p className="text-xs text-white/60 font-mono bg-charcoal/30 p-2 rounded border border-white/5 italic whitespace-pre-wrap">
                                    {attempt.response}
                                  </p>
                                </div>
                              </div>
                            </div>

                            <div className="flex flex-col items-end gap-2">
                              <div className="text-right">
                                <p
                                  className={`text-sm font-bold ${
                                    (attempt.verdict.risk_score ?? 0) > 70
                                      ? "text-error-red"
                                      : "text-white"
                                  }`}
                                >
                                  {attempt.verdict.risk_score ?? 0}
                                </p>
                                <p className="text-[10px] text-white/20 uppercase">
                                  Risk
                                </p>
                              </div>
                              <ChevronRight
                                size={16}
                                className={`transition-colors ${selectedAttempt?.id === attempt.id ? "text-cyan-accent" : "text-white/10"}`}
                              />
                            </div>
                          </div>
                        </motion.div>
                          ))}
                        </div>
                      ))}

                      {isAttacking && (
                        <div className="p-8 flex flex-col items-center justify-center space-y-4 opacity-40">
                          <div className="w-8 h-8 border-2 border-cyan-accent/20 border-t-cyan-accent rounded-full animate-spin" />
                          <p className="text-xs font-mono animate-pulse">
                            Awaiting response from target...
                          </p>
                        </div>
                      )}
                    </div>
                  </div>
                ) : (
                  <div className="h-[60vh] flex flex-col items-center justify-center text-center space-y-6">
                    <div className="w-20 h-20 bg-cyan-accent/10 rounded-3xl flex items-center justify-center text-cyan-accent">
                      <Terminal size={40} />
                    </div>
                    <div className="space-y-2 max-w-sm">
                      <h2 className="text-xl font-bold text-white">
                        Ready for Deployment
                      </h2>
                      <p className="text-sm text-white/40 leading-relaxed">
                        Configure your attack objective and launch a probe to
                        begin testing the resilience of your target LLM.
                      </p>
                    </div>
                    <button
                      onClick={() =>
                        document.querySelector("textarea")?.focus()
                      }
                      className="px-8 py-3 bg-white/5 hover:bg-white/10 rounded-full text-sm font-bold transition-all border border-white/10"
                    >
                      Define Objective
                    </button>
                  </div>
                )}
              </div>
            </div>
          </div>
        ) : view === "targets" ? (
          <div className="flex-1 overflow-y-auto p-8">
            <div className="max-w-5xl mx-auto space-y-8">
              {/* Target Header */}
              <div className="flex items-center justify-between">
                <div className="flex items-center gap-4">
                  <div
                    className={`w-12 h-12 rounded-xl flex items-center justify-center ${
                      selectedTarget.type === "Slack"
                        ? "bg-[#4A154B] text-white"
                        : selectedTarget.type === "Local"
                          ? "bg-amber-accent/20 text-amber-accent"
                          : "bg-cyan-accent/20 text-cyan-accent"
                    }`}
                  >
                    {selectedTarget.type === "Slack" ? (
                      <Zap size={24} />
                    ) : selectedTarget.type === "Local" ? (
                      <Terminal size={24} />
                    ) : (
                      <TargetIcon size={24} />
                    )}
                  </div>
                  <div className="space-y-1">
                    <h2 className="text-2xl font-bold text-white">
                      {selectedTarget.name}
                    </h2>
                    <div className="flex items-center gap-3">
                      <span className="text-xs text-white/40 flex items-center gap-1">
                        <div className="w-1.5 h-1.5 rounded-full bg-success-green" />
                        Operational
                      </span>
                      <span className="text-xs text-white/20">•</span>
                      <span className="text-xs text-white/40">
                        {selectedTarget.type} Endpoint
                      </span>
                    </div>
                  </div>
                </div>
                <button
                  onClick={() => setView("dashboard")}
                  className="px-6 py-2 bg-cyan-accent text-charcoal rounded-full font-bold text-sm cyan-glow"
                >
                  Launch Probe
                </button>
              </div>

              {/* Target Stats */}
              <div className="grid grid-cols-1 md:grid-cols-4 gap-4">
                {[
                  {
                    label: "Total Probes",
                    value: sessions.filter(
                      (s) => s.target === selectedTarget.name,
                    ).length,
                    icon: History,
                  },
                  {
                    label: "Vulnerabilities",
                    value: sessions.filter(
                      (s) =>
                        s.target === selectedTarget.name &&
                        s.status === "success",
                    ).length,
                    icon: ShieldAlert,
                    color: "text-error-red",
                  },
                  {
                    label: "Uptime",
                    value: "99.9%",
                    icon: CheckCircle2,
                    color: "text-success-green",
                  },
                  {
                    label: "Avg Latency",
                    value: "142ms",
                    icon: Zap,
                    color: "text-cyan-accent",
                  },
                ].map((stat, i) => (
                  <div key={i} className="glass-panel p-4 rounded-xl space-y-2">
                    <div className="flex items-center justify-between">
                      <span className="text-[10px] font-semibold uppercase tracking-widest text-white/30">
                        {stat.label}
                      </span>
                      <stat.icon size={14} className="text-white/20" />
                    </div>
                    <p
                      className={`text-xl font-bold ${stat.color || "text-white"}`}
                    >
                      {stat.value}
                    </p>
                  </div>
                ))}
              </div>

              <div className="grid grid-cols-1 lg:grid-cols-3 gap-8">
                {/* Configuration */}
                <div className="lg:col-span-1 space-y-4">
                  <h3 className="text-xs font-semibold uppercase tracking-widest text-white/40">
                    Configuration
                  </h3>
                  <div className="glass-panel rounded-2xl p-6 space-y-6">
                    <div className="space-y-2">
                      <label className="text-[10px] font-semibold text-white/30 uppercase">
                        Endpoint URL
                      </label>
                      <div className="bg-charcoal/50 p-2 rounded border border-white/5 font-mono text-xs text-cyan-accent truncate">
                        {selectedTarget.config.url}
                      </div>
                    </div>
                    {selectedTarget.type === "Slack" && (
                      <div className="space-y-2">
                        <label className="text-[10px] font-semibold text-white/30 uppercase">
                          Workspace ID
                        </label>
                        <div className="bg-charcoal/50 p-2 rounded border border-white/5 font-mono text-xs text-white/60">
                          T0123456789
                        </div>
                      </div>
                    )}
                    <div className="space-y-2">
                      <label className="text-[10px] font-semibold text-white/30 uppercase">
                        Headers
                      </label>
                      <pre className="bg-charcoal/50 p-3 rounded border border-white/5 font-mono text-[10px] text-white/40 whitespace-pre-wrap">
                        {selectedTarget.config.headers || "No custom headers"}
                      </pre>
                    </div>
                    <button className="w-full py-2 bg-white/5 hover:bg-white/10 rounded-lg text-xs font-medium transition-colors border border-white/5">
                      Edit Configuration
                    </button>
                  </div>
                </div>

                {/* Recent Activity */}
                <div className="lg:col-span-2 space-y-4">
                  <h3 className="text-xs font-semibold uppercase tracking-widest text-white/40">
                    Recent Probes
                  </h3>
                  <div className="space-y-3">
                    {(() => {
                      const targetSessions = (sessions || []).filter(
                        (s) => s.target === selectedTarget.name,
                      );
                      const display = targetSessions.length
                        ? targetSessions
                        : sessions || [];
                      return display.length > 0 ? (
                        display.map((s) => (
                          <div
                            key={s.id}
                            onClick={() => {
                              fetchSessionDetail(s.id);
                              setView("dashboard");
                            }}
                            className="glass-panel p-4 rounded-xl flex items-center justify-between hover:border-white/20 cursor-pointer transition-all group"
                          >
                            <div className="flex items-center gap-4">
                              <div
                                className={`w-2 h-2 rounded-full ${s.status === "success" ? "bg-error-red shadow-[0_0_8px_rgba(242,95,92,0.5)]" : "bg-success-green"}`}
                              />
                              <div>
                                <p className="text-sm font-medium text-white group-hover:text-cyan-accent transition-colors">
                                  {s.name}
                                </p>
                                <p className="text-[10px] text-white/30">
                                  {s.skill} •{" "}
                                  {new Date(s.created_at).toLocaleDateString()}
                                </p>
                              </div>
                            </div>
                            <div className="flex items-center gap-4">
                              <div className="text-right">
                                <p
                                  className={`text-xs font-bold ${s.status === "success" ? "text-error-red" : "text-success-green"}`}
                                >
                                  {s.status === "success"
                                    ? "VULNERABLE"
                                    : "SECURE"}
                                </p>
                                <p className="text-[10px] text-white/20">
                                  Verdict
                                </p>
                              </div>
                              <ChevronRight
                                size={16}
                                className="text-white/20 group-hover:text-white transition-colors"
                              />
                            </div>
                          </div>
                        ))
                      ) : (
                        <div className="p-12 text-center border-2 border-dashed border-white/5 rounded-2xl opacity-30">
                          <p className="text-sm">
                            No activity recorded yet.
                          </p>
                        </div>
                      );
                    })()}
                  </div>
                </div>
              </div>
            </div>
          </div>
        ) : (
          <div className="flex-1 overflow-y-auto p-8">
            <div className="max-w-3xl mx-auto space-y-8">
              <div className="space-y-2">
                <h2 className="text-2xl font-bold text-white">
                  Settings & API Keys
                </h2>
                <p className="text-sm text-white/40 text-balance">
                  Configure your environment and manage your security
                  credentials.
                </p>
              </div>

              <div className="space-y-6">
                <section className="space-y-4">
                  <h3 className="text-xs font-semibold uppercase tracking-widest text-white/40">
                    API Credentials
                  </h3>
                  <div className="glass-panel rounded-2xl p-6 space-y-6">
                    <div className="space-y-2">
                      <label className="text-[10px] font-semibold text-white/30 uppercase">
                        OpenRouter / OpenAI Compatible API Key
                      </label>
                      <input
                        type="password"
                        value={apiKey}
                        onChange={(e) => setApiKey(e.target.value)}
                        placeholder="sk-or-..."
                        className="w-full bg-charcoal/50 border border-white/10 rounded-lg px-4 py-2 text-sm text-white/60 outline-none"
                      />
                      <p className="text-[10px] text-white/30">
                        Key is kept in your browser only and sent per-request to the core process.
                      </p>
                    </div>
                    <div className="space-y-2">
                      <label className="text-[10px] font-semibold text-white/30 uppercase">
                        Base URL (optional)
                      </label>
                      <input
                        type="text"
                        value={baseUrl}
                        onChange={(e) => setBaseUrl(e.target.value)}
                        placeholder="https://openrouter.ai/api/v1"
                        className="w-full bg-charcoal/50 border border-white/10 rounded-lg px-4 py-2 text-sm text-white/60 outline-none"
                      />
                      <p className="text-[10px] text-white/30">
                        Leave blank to use default OpenAI endpoint; for OpenRouter use https://openrouter.ai/api/v1.
                      </p>
                    </div>
                    <div className="flex items-center gap-2 text-white/60 text-xs">
                      <input
                        id="allow-client-key"
                        type="checkbox"
                        checked={allowClientKey}
                        onChange={(e) => setAllowClientKey(e.target.checked)}
                        className="accent-cyan-accent"
                      />
                      <label htmlFor="allow-client-key" className="select-none">
                        Send key from browser (not recommended; prefer backend env)
                      </label>
                    </div>
                    <div className="flex gap-3">
                      <button
                        onClick={() => {
                          localStorage.setItem("promptheus_api_key", apiKey);
                          localStorage.setItem("promptheus_base_url", baseUrl);
                          localStorage.setItem(
                            "promptheus_allow_client_key",
                            String(allowClientKey),
                          );
                          setSuccessMessage("Saved API settings");
                        }}
                        className="px-4 py-2 bg-cyan-accent text-charcoal rounded-lg text-xs font-bold cyan-glow"
                      >
                        Save locally
                      </button>
                      <button
                        onClick={() => {
                          setApiKey("");
                          setBaseUrl("");
                          localStorage.removeItem("promptheus_api_key");
                          localStorage.removeItem("promptheus_base_url");
                        }}
                        className="px-4 py-2 bg-white/10 text-white rounded-lg text-xs border border-white/10"
                      >
                        Clear
                      </button>
                    </div>
                  </div>
                </section>

                <section className="space-y-4">
                  <h3 className="text-xs font-semibold uppercase tracking-widest text-white/40">
                    Platform Preferences
                  </h3>
                  <div className="glass-panel rounded-2xl p-6 space-y-4">
                    {[
                      {
                        label: "Auto-Judge Probes",
                        desc: "Automatically evaluate responses using Gemini judge.",
                        enabled: true,
                      },
                      {
                        label: "Live Streaming",
                        desc: "Stream attack attempts in real-time to the dashboard.",
                        enabled: true,
                      },
                      {
                        label: "Notification Sounds",
                        desc: "Play sound alerts when a vulnerability is detected.",
                        enabled: false,
                      },
                    ].map((pref, i) => (
                      <div
                        key={i}
                        className="flex items-center justify-between py-2 border-b border-white/5 last:border-0"
                      >
                        <div className="space-y-0.5">
                          <p className="text-sm font-medium text-white">
                            {pref.label}
                          </p>
                          <p className="text-[10px] text-white/30">
                            {pref.desc}
                          </p>
                        </div>
                        <button
                          className={`w-10 h-5 rounded-full relative transition-colors ${pref.enabled ? "bg-cyan-accent" : "bg-white/10"}`}
                        >
                          <div
                            className={`absolute top-1 w-3 h-3 bg-white rounded-full transition-all ${pref.enabled ? "left-6" : "left-1"}`}
                          />
                        </button>
                      </div>
                    ))}
                  </div>
                </section>

                <section className="space-y-4">
                  <h3 className="text-xs font-semibold uppercase tracking-widest text-error-red/60">
                    Danger Zone
                  </h3>
                  <div className="glass-panel rounded-2xl p-6 border-error-red/20 bg-error-red/5">
                    <div className="flex items-center justify-between">
                      <div className="space-y-1">
                        <p className="text-sm font-medium text-white">
                          Clear Session History
                        </p>
                        <p className="text-[10px] text-white/40">
                          Permanently delete all past probes and attack data.
                        </p>
                      </div>
                      <button
                        onClick={deleteHistory}
                        className="px-4 py-2 bg-error-red/20 hover:bg-error-red/30 text-error-red text-xs font-bold rounded-lg transition-all border border-error-red/20"
                      >
                        Delete All Data
                      </button>
                    </div>
                  </div>
                </section>
              </div>
            </div>
          </div>
        )}
      </main>

      {/* Right Sidebar: Judge Insight */}
      <AnimatePresence>
        {isSidebarOpen && (
          <motion.aside
            initial={{ width: 0, opacity: 0 }}
            animate={{ width: 320, opacity: 1 }}
            exit={{ width: 0, opacity: 0 }}
            className="glass-panel border-l border-white/5 flex flex-col z-10"
          >
            <div className="p-4 border-b border-white/5 flex items-center justify-between">
              <h2 className="font-bold text-sm flex items-center gap-2">
                <ShieldCheck size={16} className="text-cyan-accent" />
                Judge Insight
              </h2>
              <button
                onClick={() => setIsSidebarOpen(false)}
                className="p-1 hover:bg-white/5 rounded text-white/40"
              >
                <ChevronRight size={16} />
              </button>
            </div>

            <div className="flex-1 overflow-y-auto p-4 space-y-6">
              {selectedAttempt ? (
                <>
                  <section className="space-y-3">
                    <div className="flex items-center justify-between">
                      <h3 className="text-xs font-semibold uppercase tracking-widest text-white/40">
                        Verdict
                      </h3>
                      <span className="text-[10px] text-white/30">
                        ID: {selectedAttempt?.id?.slice(0, 8) || "—"}
                      </span>
                    </div>
                    <div
                      className={`p-4 rounded-xl border ${selectedAttempt.verdict.is_vulnerable ? "bg-error-red/5 border-error-red/20" : "bg-success-green/5 border-success-green/20"}`}
                    >
                      <div className="flex items-center justify-between mb-2">
                        <div className="flex flex-col">
                          <span
                            className={`text-sm font-bold ${selectedAttempt.verdict.is_vulnerable ? "text-error-red" : "text-success-green"}`}
                          >
                            {selectedAttempt.verdict.is_vulnerable
                              ? "VULNERABLE"
                              : "SECURE"}
                          </span>
                          <span className="text-[10px] text-white/40">
                            {selectedAttempt.verdict.category}
                          </span>
                        </div>
                        {selectedAttempt.verdict.is_vulnerable ? (
                          <XCircle size={18} className="text-error-red" />
                        ) : (
                          <CheckCircle2
                            size={18}
                            className="text-success-green"
                          />
                        )}
                      </div>
                      <p className="text-xs text-white/70 leading-relaxed">
                        {selectedAttempt.verdict.reason || "No reasoning provided."}
                      </p>
                    </div>
                  </section>

                  <section className="grid grid-cols-2 gap-3">
                    <div className="glass-panel p-3 rounded-xl space-y-1">
                      <span className="text-[10px] font-semibold uppercase tracking-widest text-white/30">
                        Risk Score
                      </span>
                      <div className="flex items-end gap-1">
                        <span
                          className={`text-lg font-bold ${selectedAttempt.verdict.risk_score > 70 ? "text-error-red" : selectedAttempt.verdict.risk_score > 30 ? "text-amber-accent" : "text-success-green"}`}
                        >
                          {selectedAttempt.verdict.risk_score}
                        </span>
                        <span className="text-[10px] text-white/20 mb-1">
                          /100
                        </span>
                      </div>
                    </div>
                    <div className="glass-panel p-3 rounded-xl space-y-1">
                      <span className="text-[10px] font-semibold uppercase tracking-widest text-white/30">
                        Confidence
                      </span>
                      <div className="flex items-center gap-2">
                        <span className="text-sm font-bold text-white">
                          {selectedAttempt.verdict.confidence}
                        </span>
                        <div className="flex gap-0.5">
                          {[1, 2, 3].map((i) => (
                            <div
                              key={`conf-${i}`}
                              className={`w-1 h-3 rounded-full ${
                                selectedAttempt.verdict.confidence === "High"
                                  ? "bg-cyan-accent"
                                  : selectedAttempt.verdict.confidence ===
                                        "Medium" && i <= 2
                                    ? "bg-amber-accent"
                                    : selectedAttempt.verdict.confidence ===
                                          "Low" && i === 1
                                      ? "bg-error-red"
                                      : "bg-white/10"
                              }`}
                            />
                          ))}
                        </div>
                      </div>
                    </div>
                  </section>

                  <section className="space-y-3">
                    <h3 className="text-xs font-semibold uppercase tracking-widest text-white/40">
                      Mitigation Strategy
                    </h3>
                    <div className="p-3 bg-cyan-accent/5 border border-cyan-accent/10 rounded-lg text-xs text-cyan-accent/80 leading-relaxed italic">
                      {selectedAttempt.verdict.mitigation || "No mitigation provided."}
                    </div>
                  </section>

                  <section className="space-y-3">
                    <h3 className="text-xs font-semibold uppercase tracking-widest text-white/40">
                      Heuristics
                    </h3>
                    <div className="flex flex-wrap gap-2">
                      {(selectedAttempt?.verdict?.heuristics || []).map((h, i) => (
                        <span
                          key={`${selectedAttempt.id}-heur-${i}`}
                          className="px-2 py-1 bg-white/5 border border-white/10 rounded text-[10px] text-white/60"
                        >
                          {h}
                        </span>
                      ))}
                    </div>
                  </section>

                  <section className="space-y-3">
                    <div className="flex items-center justify-between">
                      <h3 className="text-xs font-semibold uppercase tracking-widest text-white/40">
                        Raw Analysis
                      </h3>
                      <button
                        onClick={() =>
                          navigator.clipboard.writeText(
                            JSON.stringify(selectedAttempt.verdict, null, 2),
                          )
                        }
                        className="text-[10px] text-cyan-accent hover:underline flex items-center gap-1"
                      >
                        <Copy size={10} /> Copy JSON
                      </button>
                    </div>
                    <div className="bg-charcoal p-3 rounded-lg border border-white/5 font-mono text-[10px] text-cyan-accent/80 overflow-x-auto">
                      <pre>
                        {JSON.stringify(selectedAttempt.verdict, null, 2)}
                      </pre>
                    </div>
                  </section>
                </>
              ) : (
                <div className="h-full flex flex-col items-center justify-center text-center p-6 space-y-4 opacity-20">
                  <ShieldCheck size={48} />
                  <p className="text-sm">
                    Select an attempt to view judge analysis
                  </p>
                </div>
              )}
            </div>

            <div className="p-4 border-t border-white/5 grid grid-cols-2 gap-2">
              <button className="flex items-center justify-center gap-2 py-2 bg-white/5 hover:bg-white/10 rounded text-xs transition-colors">
                <Download size={14} />
                Export
              </button>
              <button className="flex items-center justify-center gap-2 py-2 bg-white/5 hover:bg-white/10 rounded text-xs transition-colors">
                <ExternalLink size={14} />
                Share
              </button>
            </div>
          </motion.aside>
        )}
      </AnimatePresence>

      {!isSidebarOpen && (
        <button
          onClick={() => setIsSidebarOpen(true)}
          className="fixed right-0 top-1/2 -translate-y-1/2 w-6 h-12 bg-panel border border-white/5 rounded-l-lg flex items-center justify-center text-white/40 hover:text-white transition-colors z-30"
        >
          <ChevronLeft size={16} />
        </button>
      )}

      {/* Notifications / Toasts */}
      <div className="fixed bottom-6 left-1/2 -translate-x-1/2 z-50 pointer-events-none">
        <AnimatePresence>
          {isAttacking && (
            <motion.div
              initial={{ opacity: 0, y: 20 }}
              animate={{ opacity: 1, y: 0 }}
              exit={{ opacity: 0, scale: 0.95 }}
              className="bg-cyan-accent text-charcoal px-4 py-2 rounded-full shadow-2xl flex items-center gap-3 font-bold text-sm cyan-glow pointer-events-auto"
            >
              <div className="w-2 h-2 bg-charcoal rounded-full animate-ping" />
              Attack in progress: {activeSession?.attempts?.length || 0} /{" "}
              {attemptsCount}
            </motion.div>
          )}
          {errorMessage && (
            <motion.div
              initial={{ opacity: 0, y: 20 }}
              animate={{ opacity: 1, y: 0 }}
              exit={{ opacity: 0, scale: 0.95 }}
              className="mt-2 bg-error-red text-white px-4 py-2 rounded-full shadow-2xl flex items-center gap-3 font-bold text-sm pointer-events-auto"
            >
              <XCircle size={14} /> {errorMessage}
            </motion.div>
          )}
          {successMessage && !isAttacking && (
            <motion.div
              initial={{ opacity: 0, y: 20 }}
              animate={{ opacity: 1, y: 0 }}
              exit={{ opacity: 0, scale: 0.95 }}
              className="mt-2 bg-success-green text-charcoal px-4 py-2 rounded-full shadow-2xl flex items-center gap-3 font-bold text-sm pointer-events-auto"
            >
              <CheckCircle2 size={14} /> {successMessage}
            </motion.div>
          )}
        </AnimatePresence>
      </div>
    </div>
  );
}
