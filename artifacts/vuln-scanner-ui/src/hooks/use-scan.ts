import { useState, useEffect, useRef, useCallback } from "react";
import { ScanStatusResponse, ScanResultResponse } from "../types";

export type AppState = "form" | "scanning" | "results";

export interface ScanOptions {
  target: string;
  authorized: boolean;
  delay: number;
  max_depth: number;
  max_pages: number;
  cookie: string;
  checks: string[];
  recon_modules: string[];
}

export function useScan() {
  const [appState, setAppState] = useState<AppState>("form");
  const [jobId, setJobId] = useState<string | null>(null);
  const [status, setStatus] = useState<ScanStatusResponse | null>(null);
  const [result, setResult] = useState<ScanResultResponse | null>(null);
  const [error, setError] = useState<string | null>(null);

  const startScan = async (options: ScanOptions) => {
    try {
      setError(null);
      const res = await fetch("/api/scan", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({
          ...options,
          delay: Number(options.delay),
          max_depth: Number(options.max_depth),
          max_pages: Number(options.max_pages),
        }),
      });
      if (!res.ok) {
        throw new Error(`Failed to start scan: ${res.statusText}`);
      }
      const data = await res.json();
      if (data.job_id) {
        setJobId(data.job_id);
        setAppState("scanning");
        setStatus({
          status: "running",
          stage: "INIT",
          log: ["Scan initialized...", `Target: ${options.target}`],
          stats: { pages_crawled: 0, checks_run: 0, recon_modules: 0, total_findings: 0 }
        });
      }
    } catch (err: any) {
      setError(err.message);
    }
  };

  const abortScan = () => {
    setJobId(null);
    setAppState("form");
    setStatus(null);
    setResult(null);
  };

  const fetchResult = async (id: string) => {
    try {
      const res = await fetch(`/api/result/${id}`);
      if (!res.ok) throw new Error("Failed to fetch result");
      const data = await res.json();
      setResult(data);
      setAppState("results");
    } catch (err: any) {
      setError(err.message);
    }
  };

  useEffect(() => {
    let interval: ReturnType<typeof setInterval>;

    const pollStatus = async () => {
      if (!jobId || appState !== "scanning") return;

      try {
        const res = await fetch(`/api/status/${jobId}`);
        if (!res.ok) return;
        const data: ScanStatusResponse = await res.json();
        
        setStatus((prev) => {
          // Merge logs if needed, but let's assume API returns full log for now, or we just use API log
          return data;
        });

        if (data.status === "done") {
          fetchResult(jobId);
        } else if (data.status === "error") {
          setError("Scan ended with an error state on the server.");
          setAppState("results"); // or error state
        }
      } catch (err) {
        console.error("Polling error", err);
      }
    };

    if (appState === "scanning" && jobId) {
      interval = setInterval(pollStatus, 1200);
    }

    return () => {
      if (interval) clearInterval(interval);
    };
  }, [jobId, appState]);

  return {
    appState,
    jobId,
    status,
    result,
    error,
    startScan,
    abortScan,
  };
}
