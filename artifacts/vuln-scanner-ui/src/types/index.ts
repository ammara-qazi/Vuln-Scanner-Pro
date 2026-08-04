export interface Finding {
  type: string;
  severity: "Critical" | "High" | "Medium" | "Low" | "Info";
  url: string;
  location: string;
  description: string;
  evidence: string;
  recommendation: string;
  test_url?: string;
}

export interface ReconData {
  dns?: {
    hostname: string;
    a_records: string[];
    mx_records: string[];
    ns_records: string[];
    txt_records: string[];
    subdomains_found: Array<{ subdomain: string; ips: string[] }>;
    findings: Finding[];
  };
  ports?: {
    host: string;
    open_ports: Array<{ port: number; service: string; risk: string }>;
    findings: Finding[];
  };
  ssl?: {
    tls_available: boolean;
    protocol: string;
    cipher: string;
    days_until_expiry: number;
    certificate: { subject: any; issuer: any; not_after: string; san: string[] };
    findings: Finding[];
  };
  tech?: {
    technologies: Array<{ technology: string; evidence: string }>;
    findings: Finding[];
  };
}

export interface ScanStatusResponse {
  status: "running" | "done" | "error";
  stage: string;
  log: string[];
  stats: {
    pages_crawled: number;
    checks_run: number;
    recon_modules: number;
    total_findings: number;
  };
}

export interface ScanResultResponse {
  target: string;
  stats: {
    pages_crawled: number;
    checks_run: number;
    recon_modules: number;
    total_findings: number;
    duration_ms?: number;
  };
  severity_summary: {
    Critical: number;
    High: number;
    Medium: number;
    Low: number;
    Info: number;
  };
  findings: Finding[];
  recon: ReconData;
}
