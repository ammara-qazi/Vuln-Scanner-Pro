import { useState } from "react";
import { ScanOptions } from "../hooks/use-scan";
import { AlertCircle, ChevronDown, ChevronUp, Terminal } from "lucide-react";

const ALL_CHECKS = [
  "headers",
  "server-info",
  "directory-listing",
  "sensitive-files",
  "open-redirect",
  "lfi",
  "xss",
  "sqli",
  "cors",
  "ssrf",
  "cmdi",
  "clickjacking",
];

const ALL_RECON = ["dns", "ports", "ssl", "tech"];

interface ScanFormProps {
  onInitiate: (opts: ScanOptions) => void;
  disabled?: boolean;
}

export function ScanForm({ onInitiate, disabled }: ScanFormProps) {
  const [target, setTarget] = useState("");
  const [authorized, setAuthorized] = useState(false);
  const [advancedOpen, setAdvancedOpen] = useState(false);

  const [delay, setDelay] = useState<number>(0);
  const [maxDepth, setMaxDepth] = useState<number>(3);
  const [maxPages, setMaxPages] = useState<number>(50);
  const [cookie, setCookie] = useState("");
  
  const [checks, setChecks] = useState<string[]>(ALL_CHECKS);
  const [recon, setRecon] = useState<string[]>(ALL_RECON);

  const toggleCheck = (c: string) => {
    setChecks(prev => prev.includes(c) ? prev.filter(x => x !== c) : [...prev, c]);
  };

  const toggleRecon = (r: string) => {
    setRecon(prev => prev.includes(r) ? prev.filter(x => x !== r) : [...prev, r]);
  };

  const isReady = target.length > 5 && authorized && target.startsWith("http");

  const handleSubmit = (e: React.FormEvent) => {
    e.preventDefault();
    if (!isReady) return;
    onInitiate({
      target,
      authorized,
      delay,
      max_depth: maxDepth,
      max_pages: maxPages,
      cookie,
      checks,
      recon_modules: recon
    });
  };

  return (
    <form onSubmit={handleSubmit} className="w-full max-w-4xl mx-auto space-y-6">
      {/* Target Input */}
      <div className="bg-card border border-border p-4 shadow-xl">
        <div className="flex items-center space-x-2 text-xl md:text-3xl font-bold mb-2">
          <span className="text-primary glow-text shrink-0">{`TARGET > `}</span>
          <input
            type="text"
            value={target}
            onChange={(e) => setTarget(e.target.value)}
            placeholder="https://example.com"
            className="bg-transparent border-none outline-none w-full text-foreground placeholder:text-muted-foreground focus:ring-0 p-0"
            disabled={disabled}
            autoFocus
          />
        </div>
      </div>

      {/* Authorization */}
      <label className={`flex items-start space-x-3 p-4 border transition-all cursor-pointer ${authorized ? 'border-primary glow-border bg-primary/5' : 'border-destructive bg-destructive/5'}`}>
        <div className="mt-1">
          <input 
            type="checkbox" 
            className="hidden" 
            checked={authorized}
            onChange={(e) => setAuthorized(e.target.checked)}
            disabled={disabled}
          />
          <div className={`w-6 h-6 border-2 flex items-center justify-center transition-colors ${authorized ? 'border-primary' : 'border-destructive'}`}>
            {authorized && <div className="w-3 h-3 bg-primary" />}
          </div>
        </div>
        <div>
          <h3 className={`text-lg font-bold uppercase ${authorized ? 'text-primary' : 'text-destructive'}`}>
            Authorization Confirmed
          </h3>
          <p className="text-sm text-muted-foreground mt-1">
            I confirm I have explicit written authorization to perform security testing against this target. 
            I understand that unauthorized scanning is illegal.
          </p>
        </div>
      </label>

      {/* Advanced Options */}
      <div className="border border-border bg-card">
        <button 
          type="button" 
          onClick={() => setAdvancedOpen(!advancedOpen)}
          className="w-full flex items-center justify-between p-4 hover:bg-muted/30 transition-colors"
        >
          <span className="font-bold uppercase tracking-wider flex items-center gap-2">
            <Terminal size={18} />
            Advanced Options
          </span>
          {advancedOpen ? <ChevronUp size={20} /> : <ChevronDown size={20} />}
        </button>

        {advancedOpen && (
          <div className="p-4 border-t border-border grid grid-cols-1 md:grid-cols-2 gap-6">
            <div className="space-y-4">
              <div>
                <label className="block text-sm text-muted-foreground mb-1 uppercase">Request Delay (seconds)</label>
                <input 
                  type="number" 
                  step="0.1" 
                  min="0"
                  max="5"
                  value={delay}
                  onChange={e => setDelay(Number(e.target.value))}
                  className="w-full bg-background border border-border p-2 text-foreground focus:border-primary focus:outline-none"
                />
              </div>
              <div>
                <label className="block text-sm text-muted-foreground mb-1 uppercase">Max Crawl Depth</label>
                <input 
                  type="number" 
                  min="1"
                  max="10"
                  value={maxDepth}
                  onChange={e => setMaxDepth(Number(e.target.value))}
                  className="w-full bg-background border border-border p-2 text-foreground focus:border-primary focus:outline-none"
                />
              </div>
              <div>
                <label className="block text-sm text-muted-foreground mb-1 uppercase">Max Pages</label>
                <input 
                  type="number" 
                  min="1"
                  max="500"
                  value={maxPages}
                  onChange={e => setMaxPages(Number(e.target.value))}
                  className="w-full bg-background border border-border p-2 text-foreground focus:border-primary focus:outline-none"
                />
              </div>
              <div>
                <label className="block text-sm text-muted-foreground mb-1 uppercase">Session Cookie (Optional)</label>
                <input 
                  type="text" 
                  value={cookie}
                  onChange={e => setCookie(e.target.value)}
                  placeholder="session=..."
                  className="w-full bg-background border border-border p-2 text-foreground focus:border-primary focus:outline-none font-mono text-sm"
                />
              </div>
            </div>

            <div className="space-y-6">
              <div>
                <label className="block text-sm text-muted-foreground mb-2 uppercase flex justify-between">
                  <span>Recon Modules</span>
                  <button type="button" className="text-xs hover:text-primary" onClick={() => setRecon(ALL_RECON)}>All</button>
                </label>
                <div className="flex flex-wrap gap-2">
                  {ALL_RECON.map(r => (
                    <button
                      key={r}
                      type="button"
                      onClick={() => toggleRecon(r)}
                      className={`px-3 py-1 text-xs border uppercase transition-colors ${
                        recon.includes(r) ? 'border-primary text-primary bg-primary/10' : 'border-border text-muted-foreground'
                      }`}
                    >
                      {r}
                    </button>
                  ))}
                </div>
              </div>

              <div>
                <label className="block text-sm text-muted-foreground mb-2 uppercase flex justify-between">
                  <span>Vulnerability Checks</span>
                  <button type="button" className="text-xs hover:text-primary" onClick={() => setChecks(ALL_CHECKS)}>All</button>
                </label>
                <div className="flex flex-wrap gap-2">
                  {ALL_CHECKS.map(c => (
                    <button
                      key={c}
                      type="button"
                      onClick={() => toggleCheck(c)}
                      className={`px-3 py-1 text-xs border uppercase transition-colors ${
                        checks.includes(c) ? 'border-primary text-primary bg-primary/10' : 'border-border text-muted-foreground'
                      }`}
                    >
                      {c}
                    </button>
                  ))}
                </div>
              </div>
            </div>
          </div>
        )}
      </div>

      <button
        type="submit"
        disabled={!isReady || disabled}
        className={`w-full py-4 text-2xl font-bold uppercase transition-all flex items-center justify-center gap-3 ${
          isReady 
            ? 'bg-primary text-primary-foreground hover:bg-primary/90 animate-pulse-glow glow-border' 
            : 'bg-muted text-muted-foreground cursor-not-allowed border border-border'
        }`}
      >
        <span>Initiate Scan</span>
        {isReady && <Terminal size={24} />}
      </button>

      {!target.startsWith("http") && target.length > 0 && (
        <div className="text-destructive text-sm flex items-center gap-2 justify-center">
          <AlertCircle size={16} /> Target must start with http:// or https://
        </div>
      )}
    </form>
  );
}
