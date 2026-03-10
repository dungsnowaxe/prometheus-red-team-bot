import { useEffect, useRef, useState, useCallback } from "react";

const SCROLL_THRESHOLD = 50; // pixels from bottom to consider "at bottom"

export function LogViewer({ log, visible }) {
  const bottomRef = useRef(null);
  const containerRef = useRef(null);
  const [isUserScrolledUp, setIsUserScrolledUp] = useState(false);

  // Check if user is at or near the bottom of the log
  const isAtBottom = useCallback(() => {
    const container = containerRef.current;
    if (!container) return true;
    return container.scrollHeight - container.scrollTop <= container.clientHeight + SCROLL_THRESHOLD;
  }, []);

  // Handle scroll events to detect if user scrolled away from bottom
  const handleScroll = useCallback(() => {
    const atBottom = isAtBottom();
    setIsUserScrolledUp(!atBottom);
  }, [isAtBottom]);

  // Auto-scroll only if user hasn't scrolled up
  useEffect(() => {
    if (!isUserScrolledUp && bottomRef.current) {
      bottomRef.current.scrollIntoView({ behavior: "smooth" });
    }
  }, [log, isUserScrolledUp]);

  // Reset scroll state when log becomes empty (new scan starting)
  useEffect(() => {
    if (!log) {
      setIsUserScrolledUp(false);
    }
  }, [log]);

  if (!visible) return null;

  return (
    <div
      ref={containerRef}
      onScroll={handleScroll}
      className="h-48 w-full overflow-auto rounded-lg border bg-zinc-950 p-3"
    >
      <pre className="font-mono text-xs leading-relaxed text-zinc-300 whitespace-pre-wrap break-all">
        {log || "Waiting for output..."}
      </pre>
      <div ref={bottomRef} />
    </div>
  );
}
