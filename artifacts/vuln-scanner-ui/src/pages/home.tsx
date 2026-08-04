import { useScan } from "../hooks/use-scan";
import { ScanForm } from "../components/ScanForm";
import { LiveTerminal } from "../components/LiveTerminal";
import { ResultsPanel } from "../components/ResultsPanel";
import { AlertCircle } from "lucide-react";
import { useEffect, useState } from "react";

export default function Home() {
  const { appState, status, result, error, jobId, startScan, abortScan } = useScan();
  const [startTime, setStartTime] = useState<number>(0);
  const [currentTarget, setCurrentTarget] = useState<string>("");

  useEffect(() => {
    if (appState === "scanning" && startTime === 0) {
      setStartTime(Date.now());
    } else if (appState === "form") {
      setStartTime(0);
    }
  }, [appState, startTime]);

  const handleInitiate = (opts: any) => {
    setCurrentTarget(opts.target);
    startScan(opts);
  };

  return (
    <div className="min-h-screen w-full relative overflow-x-hidden selection:bg-primary/30 selection:text-primary pb-20">
      <div className="scanline" />
      
      {/* Navbar / Header */}
      <header className="sticky top-0 z-40 bg-background/90 backdrop-blur-sm border-b border-border p-4 flex flex-col md:flex-row items-start md:items-center justify-between gap-4">
        <div className="font-mono text-lg md:text-xl font-bold text-primary flex items-center">
          <span className="text-muted-foreground mr-2">[ root@wvs ]─[ ~/scan ]─$</span> 
          WebVulnScanner v2.0
          <span className="w-2 h-5 bg-primary ml-1 inline-block cursor-blink" />
        </div>
        <div className="text-xs font-mono border border-destructive text-destructive px-2 py-1 uppercase tracking-widest bg-destructive/10 shrink-0">
          Authorized Use Only
        </div>
      </header>

      <main className="container mx-auto p-4 md:p-8 mt-4 relative z-10">
        
        {error && (
          <div className="mb-8 p-4 border border-destructive bg-destructive/10 text-destructive flex items-center gap-3 font-mono animate-in slide-in-from-top-2">
            <AlertCircle />
            <div>
              <div className="font-bold">SYSTEM ERROR</div>
              <div className="text-sm">{error}</div>
            </div>
          </div>
        )}

        {appState === "form" && (
          <div className="animate-in fade-in zoom-in-95 duration-300">
            <div className="text-center mb-12 mt-8">
              <h2 className="text-4xl font-bold uppercase tracking-widest mb-4 glow-text">Initialize Scan</h2>
              <p className="text-muted-foreground font-mono max-w-2xl mx-auto">
                Configure target parameters and authorization. The system will perform aggressive 
                vulnerability probing. All activity is logged.
              </p>
            </div>
            <ScanForm onInitiate={handleInitiate} />
          </div>
        )}

        {appState === "scanning" && (
          <div className="animate-in fade-in duration-300">
            <LiveTerminal 
              target={currentTarget}
              status={status}
              onAbort={abortScan}
              startTime={startTime}
            />
          </div>
        )}

        {appState === "results" && result && (
          <div className="animate-in fade-in slide-in-from-bottom-8 duration-500">
            <ResultsPanel 
              result={result} 
              jobId={jobId!} 
              onNewScan={abortScan} 
            />
          </div>
        )}

      </main>
    </div>
  );
}
