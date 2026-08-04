import { ScanResultResponse, Finding } from "../types";
import { Download, AlertTriangle, Info, ChevronDown, ChevronUp, Server, ShieldAlert, Globe, Lock } from "lucide-react";
import { useState } from "react";

interface ResultsPanelProps {
  result: ScanResultResponse;
  jobId: string;
  onNewScan: () => void;
}

export function ResultsPanel({ result, jobId, onNewScan }: ResultsPanelProps) {
  const [expandedFinding, setExpandedFinding] = useState<number | null>(null);

  const downloadReport = (format: string) => {
    window.open(`/api/report/${jobId}/${format}`, "_blank");
  };

  const total = result.stats.total_findings;
  const isClean = total === 0;

  return (
    <div className="w-full max-w-6xl mx-auto space-y-8 animate-in fade-in slide-in-from-bottom-4 duration-700">
      
      {/* Header */}
      <div className={`p-6 border ${isClean ? 'border-primary glow-border' : 'border-destructive glow-critical'} bg-card relative overflow-hidden`}>
        <div className="absolute top-0 right-0 p-4 opacity-10">
          <ShieldAlert size={120} className={isClean ? "text-primary" : "text-destructive"} />
        </div>
        <div className="relative z-10 flex flex-col md:flex-row md:items-end justify-between gap-4">
          <div>
            <h1 className={`text-3xl md:text-5xl font-bold uppercase mb-2 ${isClean ? 'text-primary' : 'text-destructive'}`}>
              {isClean ? 'Target Secure' : 'Vulnerabilities Found'}
            </h1>
            <p className="text-xl text-muted-foreground font-mono">
              <span className="text-foreground">{result.target}</span> — {total} findings
            </p>
          </div>
          <button 
            onClick={onNewScan}
            className="px-6 py-2 border border-border hover:border-primary hover:text-primary transition-colors uppercase text-sm"
          >
            &gt; New Scan
          </button>
        </div>
      </div>

      {/* Severity Summary */}
      <div className="grid grid-cols-2 md:grid-cols-5 gap-4">
        <SeverityBadge label="Critical" count={result.severity_summary.Critical} colorClass="glow-critical bg-severity-critical" />
        <SeverityBadge label="High" count={result.severity_summary.High} colorClass="glow-high bg-severity-high" />
        <SeverityBadge label="Medium" count={result.severity_summary.Medium} colorClass="glow-medium bg-severity-medium" />
        <SeverityBadge label="Low" count={result.severity_summary.Low} colorClass="glow-low bg-severity-low" />
        <SeverityBadge label="Info" count={result.severity_summary.Info} colorClass="glow-info bg-severity-info" />
      </div>

      {/* Export Row */}
      <div className="flex flex-wrap items-center gap-4 bg-background p-4 border border-border">
        <div className="text-sm text-muted-foreground uppercase mr-auto flex items-center gap-2">
          <Download size={16} /> Export Report
        </div>
        {["json", "txt", "html", "docx"].map(ext => (
          <button
            key={ext}
            onClick={() => downloadReport(ext)}
            className="px-4 py-2 text-sm font-mono border border-border hover:border-primary hover:text-primary transition-colors flex items-center gap-2"
          >
            <span className="text-muted-foreground">&gt; export</span> {ext}
          </button>
        ))}
      </div>

      <div className="grid grid-cols-1 lg:grid-cols-3 gap-8 items-start">
        {/* Main Findings List */}
        <div className="lg:col-span-2 space-y-4">
          <h2 className="text-xl font-bold uppercase text-primary border-b border-border pb-2 flex items-center gap-2">
            <AlertTriangle size={20} /> Security Findings
          </h2>
          
          {result.findings.length === 0 ? (
            <div className="p-8 border border-border bg-card text-center text-muted-foreground font-mono">
              [root@wvs] ~ $ No vulnerabilities detected.
            </div>
          ) : (
            <div className="space-y-3">
              {result.findings.map((f, i) => (
                <div key={i} className={`border ${getSeverityBorderClass(f.severity)} bg-card transition-all`}>
                  <div 
                    className="p-4 flex items-start sm:items-center justify-between cursor-pointer hover:bg-white/5"
                    onClick={() => setExpandedFinding(expandedFinding === i ? null : i)}
                  >
                    <div className="flex items-start sm:items-center gap-4 flex-col sm:flex-row">
                      <span className={`px-2 py-1 text-xs font-bold uppercase ${getSeverityBgClass(f.severity)}`}>
                        {f.severity}
                      </span>
                      <div>
                        <div className="font-bold text-lg">{f.type}</div>
                        <div className="text-sm text-muted-foreground truncate max-w-md">{f.url}</div>
                      </div>
                    </div>
                    {expandedFinding === i ? <ChevronUp className="text-muted-foreground" /> : <ChevronDown className="text-muted-foreground" />}
                  </div>
                  
                  {expandedFinding === i && (
                    <div className="p-4 border-t border-border bg-background/50 space-y-4 text-sm font-mono">
                      <div>
                        <div className="text-muted-foreground uppercase text-xs mb-1">Description</div>
                        <div>{f.description}</div>
                      </div>
                      <div>
                        <div className="text-muted-foreground uppercase text-xs mb-1">Location</div>
                        <div className="break-all">{f.location}</div>
                      </div>
                      <div>
                        <div className="text-muted-foreground uppercase text-xs mb-1">Evidence</div>
                        <pre className="bg-[#050805] p-3 border border-border overflow-x-auto text-xs text-primary/80 whitespace-pre-wrap">
                          {f.evidence}
                        </pre>
                      </div>
                      <div>
                        <div className="text-muted-foreground uppercase text-xs mb-1">Recommendation</div>
                        <div className="text-emerald-400">{f.recommendation}</div>
                      </div>
                      {f.test_url && (
                        <div>
                          <div className="text-muted-foreground uppercase text-xs mb-1">Test URL</div>
                          <a href={f.test_url} target="_blank" rel="noreferrer" className="text-blue-400 hover:underline break-all">
                            {f.test_url}
                          </a>
                        </div>
                      )}
                    </div>
                  )}
                </div>
              ))}
            </div>
          )}
        </div>

        {/* Recon Side Panel */}
        <div className="space-y-4">
          <h2 className="text-xl font-bold uppercase text-primary border-b border-border pb-2 flex items-center gap-2">
            <Info size={20} /> Recon Data
          </h2>
          
          <div className="space-y-4">
            {result.recon.dns && (
              <ReconCard title="DNS Information" icon={<Globe size={16} />}>
                <div className="text-sm">
                  <div className="text-muted-foreground">A Records: <span className="text-foreground">{result.recon.dns.a_records?.join(", ") || "None"}</span></div>
                  <div className="text-muted-foreground mt-2">Subdomains:</div>
                  <ul className="list-disc list-inside mt-1">
                    {result.recon.dns.subdomains_found?.slice(0,5).map((s,i) => (
                      <li key={i}>{s.subdomain} <span className="text-muted-foreground text-xs">({s.ips.join(", ")})</span></li>
                    ))}
                    {(result.recon.dns.subdomains_found?.length || 0) > 5 && (
                      <li className="text-muted-foreground">...and {(result.recon.dns.subdomains_found?.length || 0) - 5} more</li>
                    )}
                  </ul>
                </div>
              </ReconCard>
            )}

            {result.recon.ports && (
              <ReconCard title="Open Ports" icon={<Server size={16} />}>
                <div className="flex flex-wrap gap-2 text-sm">
                  {result.recon.ports.open_ports?.map((p,i) => (
                    <span key={i} className="px-2 py-1 bg-muted border border-border">
                      {p.port}/{p.service}
                    </span>
                  ))}
                  {(!result.recon.ports.open_ports || result.recon.ports.open_ports.length === 0) && (
                    <span className="text-muted-foreground">No open ports detected beyond 80/443.</span>
                  )}
                </div>
              </ReconCard>
            )}

            {result.recon.ssl && (
              <ReconCard title="SSL/TLS" icon={<Lock size={16} />}>
                {result.recon.ssl.tls_available ? (
                  <div className="text-sm space-y-1">
                    <div>Protocol: <span className="text-foreground">{result.recon.ssl.protocol}</span></div>
                    <div>Cipher: <span className="text-foreground">{result.recon.ssl.cipher}</span></div>
                    <div className={result.recon.ssl.days_until_expiry < 30 ? "text-destructive" : "text-primary"}>
                      Expires in {result.recon.ssl.days_until_expiry} days
                    </div>
                  </div>
                ) : (
                  <div className="text-muted-foreground text-sm">TLS not available.</div>
                )}
              </ReconCard>
            )}
            
            {result.recon.tech && (
              <ReconCard title="Technologies" icon={<Server size={16} />}>
                <div className="flex flex-wrap gap-2 text-sm">
                  {result.recon.tech.technologies?.map((t,i) => (
                    <span key={i} className="px-2 py-1 text-primary border border-primary/30 bg-primary/5">
                      {t.technology}
                    </span>
                  ))}
                </div>
              </ReconCard>
            )}
          </div>
        </div>
      </div>
    </div>
  );
}

function SeverityBadge({ label, count, colorClass }: { label: string, count: number, colorClass: string }) {
  const active = count > 0;
  return (
    <div className={`p-4 border ${active ? colorClass : 'border-border bg-card'} flex flex-col items-center justify-center transition-all`}>
      <div className={`text-3xl font-bold ${!active && 'text-muted-foreground'}`}>{count}</div>
      <div className={`text-xs uppercase mt-1 ${!active && 'text-muted-foreground'}`}>{label}</div>
    </div>
  );
}

function ReconCard({ title, icon, children }: { title: string, icon: React.ReactNode, children: React.ReactNode }) {
  return (
    <div className="border border-border bg-card overflow-hidden">
      <div className="p-2 border-b border-border bg-muted/30 flex items-center gap-2 text-sm font-bold uppercase">
        {icon} {title}
      </div>
      <div className="p-3 font-mono">
        {children}
      </div>
    </div>
  );
}

function getSeverityBorderClass(sev: string) {
  switch(sev) {
    case 'Critical': return 'border-severity-critical glow-critical';
    case 'High': return 'border-severity-high';
    case 'Medium': return 'border-severity-medium';
    case 'Low': return 'border-severity-low';
    case 'Info': return 'border-severity-info';
    default: return 'border-border';
  }
}

function getSeverityBgClass(sev: string) {
  switch(sev) {
    case 'Critical': return 'bg-severity-critical';
    case 'High': return 'bg-severity-high';
    case 'Medium': return 'bg-severity-medium';
    case 'Low': return 'bg-severity-low';
    case 'Info': return 'bg-severity-info';
    default: return 'bg-muted';
  }
}
