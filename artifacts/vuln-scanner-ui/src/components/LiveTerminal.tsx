import { useEffect, useRef } from "react";
import { ScanStatusResponse } from "../types";

interface LiveTerminalProps {
  target: string;
  status: ScanStatusResponse | null;
  onAbort: () => void;
  startTime: number;
}

const STAGES = [
  "INIT",
  "RECON",
  "CRAWL",
  "HEADERS",
  "SERVER",
  "DIRS",
  "FILES",
  "XSS",
  "SQLI",
  "LFI",
  "CORS",
  "SSRF",
  "CMDI",
  "DONE"
];

export function LiveTerminal({ target, status, onAbort, startTime }: LiveTerminalProps) {
  const logEndRef = useRef<HTMLDivElement>(null);
  
  useEffect(() => {
    logEndRef.current?.scrollIntoView({ behavior: "smooth" });
  }, [status?.log]);

  const currentStage = status?.stage || "INIT";
  const stageIndex = STAGES.indexOf(currentStage);

  return (
    <div className="w-full max-w-6xl mx-auto flex flex-col h-[80vh] border border-border bg-card shadow-2xl glow-border">
      {/* Terminal Header */}
      <div className="flex items-center justify-between p-3 border-b border-border bg-background">
        <div className="flex items-center gap-4">
          <div className="text-primary font-bold">{target}</div>
          <div className="text-muted-foreground text-sm">
            JOB_ID: {Math.random().toString(36).substring(7).toUpperCase()}
          </div>
        </div>
        <button 
          onClick={onAbort}
          className="px-3 py-1 text-xs border border-destructive text-destructive hover:bg-destructive hover:text-destructive-foreground uppercase transition-colors"
        >
          Abort
        </button>
      </div>

      {/* Stage Rail */}
      <div className="flex flex-wrap items-center gap-1 p-3 border-b border-border text-[10px] sm:text-xs overflow-x-auto bg-background/50">
        {STAGES.map((s, i) => {
          const isPast = i < stageIndex;
          const isCurrent = i === stageIndex;
          return (
            <div key={s} className="flex items-center">
              <span className={`px-2 py-1 border transition-colors ${
                isCurrent ? 'bg-primary text-primary-foreground border-primary glow-border' : 
                isPast ? 'border-primary text-primary bg-primary/10' : 'border-border text-muted-foreground'
              }`}>
                {s}
              </span>
              {i < STAGES.length - 1 && (
                <span className={`w-4 h-[1px] mx-1 ${isPast ? 'bg-primary' : 'bg-border'}`} />
              )}
            </div>
          );
        })}
      </div>

      {/* Log Feed */}
      <div className="flex-1 overflow-y-auto p-4 bg-[#050805] text-sm leading-relaxed font-mono">
        {status?.log?.map((line, i) => (
          <div key={i} className="mb-1 opacity-90 break-all">
            {line.includes("[CRITICAL]") ? (
              <span className="text-severity-critical font-bold">{line}</span>
            ) : line.includes("[HIGH]") ? (
              <span className="text-severity-high">{line}</span>
            ) : line.includes("[INFO]") ? (
              <span className="text-severity-info">{line}</span>
            ) : line.includes("[OK]") ? (
              <span className="text-primary">{line}</span>
            ) : (
              <span className="text-muted-foreground">{line}</span>
            )}
          </div>
        ))}
        {status?.status === "running" && (
          <div className="text-primary mt-2 flex items-center">
            <span>&gt; processing</span>
            <span className="w-2 h-4 bg-primary ml-2 cursor-blink inline-block" />
          </div>
        )}
        <div ref={logEndRef} />
      </div>

      {/* Stats Footer */}
      <div className="grid grid-cols-2 md:grid-cols-4 border-t border-border bg-background">
        <StatBox label="Pages Crawled" value={status?.stats?.pages_crawled || 0} />
        <StatBox label="Checks Run" value={status?.stats?.checks_run || 0} />
        <StatBox label="Recon Modules" value={status?.stats?.recon_modules || 0} />
        <StatBox 
          label="Total Findings" 
          value={status?.stats?.total_findings || 0} 
          valueClassName={(status?.stats?.total_findings || 0) > 0 ? "text-severity-critical glow-text" : "text-primary"}
        />
      </div>
    </div>
  );
}

function StatBox({ label, value, valueClassName = "text-primary" }: { label: string, value: number, valueClassName?: string }) {
  return (
    <div className="p-3 border-r border-border last:border-r-0 flex flex-col items-center justify-center">
      <div className="text-[10px] text-muted-foreground uppercase tracking-wider mb-1">{label}</div>
      <div className={`text-xl font-bold ${valueClassName}`}>{value}</div>
    </div>
  );
}
