import React, { useState, useRef } from "react";
import { Helmet } from "react-helmet-async";
import {
  Shield,
  ShieldBan,
  ShieldAlert,
  ShieldCheck,
  Eye,
  AlertTriangle,
  CheckCircle2,
  Loader2,
  ChevronRight,
} from "lucide-react";
import { Navbar } from "@/components/layout/Navbar";
import { Footer } from "@/components/layout/Footer";
import { Button } from "@/components/ui/button";

const BASE_URL = import.meta.env.BASE_URL.replace(/\/$/, "");
const API_URL = BASE_URL.replace(/^\/[^/]+/, "/api");

const SEVERITY_ORDER = ["critical", "high", "medium", "low"] as const;

type Severity = (typeof SEVERITY_ORDER)[number];

interface Finding {
  finding_id: string;
  severity: Severity;
  category: string;
  finding_type: string;
  description: string;
  recommendation: string;
  match_start: number;
  match_end: number;
}

interface ScanResult {
  findings: Finding[];
  summary: {
    total: number;
    max_severity: Severity | null;
    categories: string[];
  };
  mode_outcomes: {
    kill: string;
    redact: string;
    pause: string;
    report_only: string;
  };
}

const SEVERITY_META: Record<Severity, { label: string; color: string; bg: string; border: string }> = {
  critical: { label: "CRITICAL", color: "text-red-400", bg: "bg-red-500/10", border: "border-red-500/40" },
  high:     { label: "HIGH",     color: "text-orange-400", bg: "bg-orange-500/10", border: "border-orange-500/40" },
  medium:   { label: "MEDIUM",   color: "text-yellow-400", bg: "bg-yellow-500/10", border: "border-yellow-500/40" },
  low:      { label: "LOW",      color: "text-blue-400", bg: "bg-blue-500/10", border: "border-blue-500/40" },
};

const CATEGORY_LABELS: Record<string, string> = {
  secret_pattern: "Secret Pattern",
  prohibited_term: "Prohibited Term",
  entropy: "High Entropy",
  sensitive_file: "Sensitive File",
};

const MODE_META = [
  {
    key: "kill" as const,
    icon: <ShieldBan className="h-4 w-4 text-red-400" />,
    label: "kill",
    desc: "Hard block — raises exception",
  },
  {
    key: "redact" as const,
    icon: <ShieldAlert className="h-4 w-4 text-orange-400" />,
    label: "redact",
    desc: "Replace secrets with [REDACTED]",
  },
  {
    key: "pause" as const,
    icon: <Eye className="h-4 w-4 text-yellow-400" />,
    label: "pause",
    desc: "Pause and prompt user",
  },
  {
    key: "report_only" as const,
    icon: <ShieldCheck className="h-4 w-4 text-green-400" />,
    label: "report_only",
    desc: "Allow and audit-log only",
  },
];

const SAMPLE_PAYLOADS = [
  {
    label: "OpenAI key",
    text: `Here is my API key: sk-proj-ABCDEFghij1234567890klmnopqrstuvwxyz12345\nPlease use it to make a call.`,
  },
  {
    label: "AWS credentials",
    text: `export AWS_ACCESS_KEY_ID=AKIAIOSFODNN7EXAMPLE\nexport AWS_SECRET_ACCESS_KEY=wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY`,
  },
  {
    label: "Database URL",
    text: `Connect to postgres://admin:s3cr3tP4ssw0rd@db.internal.corp:5432/production_db`,
  },
  {
    label: "Clean text",
    text: `Summarize the latest quarterly earnings report and highlight key growth metrics for the board meeting.`,
  },
];

function SeverityBadge({ severity }: { severity: Severity }) {
  const meta = SEVERITY_META[severity];
  return (
    <span className={`inline-flex items-center px-2 py-0.5 text-xs font-mono font-bold border ${meta.color} ${meta.bg} ${meta.border}`}>
      {meta.label}
    </span>
  );
}

function FindingCard({ finding }: { finding: Finding }) {
  const meta = SEVERITY_META[finding.severity as Severity] ?? SEVERITY_META.low;
  return (
    <div className={`border ${meta.border} ${meta.bg} p-4 space-y-2`}>
      <div className="flex items-center gap-2 flex-wrap">
        <SeverityBadge severity={finding.severity as Severity} />
        <span className="text-xs font-mono text-muted-foreground px-2 py-0.5 border border-white/10 bg-white/5">
          {CATEGORY_LABELS[finding.category] ?? finding.category}
        </span>
        <span className="text-xs font-mono text-muted-foreground">
          {finding.finding_type.replace(/_/g, " ")}
        </span>
      </div>
      <p className="text-sm text-foreground">{finding.description}</p>
      <p className="text-xs text-muted-foreground">{finding.recommendation}</p>
    </div>
  );
}

export default function Demo() {
  const [text, setText] = useState("");
  const [result, setResult] = useState<ScanResult | null>(null);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const resultsRef = useRef<HTMLDivElement>(null);

  async function handleScan() {
    if (!text.trim()) return;
    setLoading(true);
    setError(null);
    setResult(null);

    try {
      const resp = await fetch(`${API_URL}/demo/scan`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ text }),
      });

      if (resp.status === 429) {
        setError("Rate limit reached — max 20 scans per minute. Try again shortly.");
        return;
      }
      if (!resp.ok) {
        const body = await resp.json().catch(() => ({}));
        setError((body as { error?: string }).error ?? `Server error ${resp.status}`);
        return;
      }

      const data: ScanResult = await resp.json();
      setResult(data);
      setTimeout(() => resultsRef.current?.scrollIntoView({ behavior: "smooth", block: "start" }), 50);
    } catch {
      setError("Network error — is the API server running?");
    } finally {
      setLoading(false);
    }
  }

  function loadSample(payload: (typeof SAMPLE_PAYLOADS)[number]) {
    setText(payload.text);
    setResult(null);
    setError(null);
  }

  const clean = result && result.summary.total === 0;

  return (
    <div className="min-h-screen flex flex-col dark bg-background selection:bg-primary/30">
      <Helmet>
        <title>Live Demo — killswitch-ai</title>
        <meta name="description" content="Paste any text and see killswitch-ai scan it instantly for secrets, API keys, and sensitive data — no install required." />
        <link rel="canonical" href="https://killswitch-ai.com/demo" />
        <meta property="og:url" content="https://killswitch-ai.com/demo" />
        <meta property="og:title" content="Live Demo — killswitch-ai" />
        <meta property="og:type" content="website" />
      </Helmet>

      <Navbar />

      <main className="flex-1 container mx-auto px-4 md:px-6 py-20 max-w-4xl">
        {/* Header */}
        <div className="mb-12">
          <div className="inline-flex items-center gap-2 px-3 py-1 border border-primary/40 bg-primary/5 text-xs font-mono tracking-widest mb-5 warning-stripe">
            <span className="blink text-primary">█</span>
            <span className="text-primary uppercase">Live Scanner</span>
            <span className="text-primary/30">|</span>
            <span className="text-muted-foreground">No install required</span>
          </div>
          <h1 className="font-display text-5xl md:text-7xl font-bold uppercase tracking-tight mb-4">
            Try it <span className="text-primary">live.</span>
          </h1>
          <p className="text-xl text-muted-foreground max-w-2xl">
            Paste any text below and the killswitch scanner will analyze it across all four detection layers — instantly, without installing anything.
          </p>
          <p className="text-sm text-muted-foreground/60 mt-2 font-mono">
            Content is never logged or stored by this demo.
          </p>
        </div>

        {/* Sample payloads */}
        <div className="mb-4">
          <p className="text-xs font-mono text-muted-foreground mb-2 uppercase tracking-widest">Load a sample →</p>
          <div className="flex flex-wrap gap-2">
            {SAMPLE_PAYLOADS.map((s) => (
              <button
                key={s.label}
                onClick={() => loadSample(s)}
                className="text-xs font-mono px-3 py-1.5 border border-white/15 bg-white/5 hover:bg-white/10 hover:border-primary/40 text-muted-foreground hover:text-foreground transition-colors"
              >
                {s.label}
              </button>
            ))}
          </div>
        </div>

        {/* Textarea */}
        <div className="relative mb-4">
          <textarea
            className="w-full h-48 bg-black/40 border border-white/15 focus:border-primary/60 focus:outline-none rounded-none p-4 font-mono text-sm text-foreground placeholder:text-muted-foreground/40 resize-y transition-colors"
            placeholder="Paste your LLM prompt here — e.g. a message with an API key, .env content, or any text you want to scan…"
            value={text}
            onChange={(e) => {
              setText(e.target.value);
              setResult(null);
              setError(null);
            }}
            maxLength={8000}
            spellCheck={false}
          />
          <span className="absolute bottom-2 right-3 text-xs font-mono text-muted-foreground/40">
            {text.length}/8000
          </span>
        </div>

        <Button
          onClick={handleScan}
          disabled={loading || !text.trim()}
          className="font-mono w-full sm:w-auto"
          size="lg"
        >
          {loading ? (
            <><Loader2 className="mr-2 h-4 w-4 animate-spin" /> Scanning…</>
          ) : (
            <><Shield className="mr-2 h-4 w-4" /> Run Scan</>
          )}
        </Button>

        {/* Error */}
        {error && (
          <div className="mt-6 flex items-start gap-3 border border-red-500/40 bg-red-500/10 p-4">
            <AlertTriangle className="h-5 w-5 text-red-400 mt-0.5 shrink-0" />
            <p className="text-sm text-red-300 font-mono">{error}</p>
          </div>
        )}

        {/* Results */}
        {result && (
          <div ref={resultsRef} className="mt-10 space-y-8 animate-in fade-in slide-in-from-bottom-4 duration-500">
            {/* Summary banner */}
            {clean ? (
              <div className="flex items-center gap-3 border border-green-500/40 bg-green-500/10 p-4">
                <CheckCircle2 className="h-6 w-6 text-green-400 shrink-0" />
                <div>
                  <p className="font-mono font-semibold text-green-300">All clear — no threats detected</p>
                  <p className="text-sm text-muted-foreground mt-0.5">
                    The scanner found nothing sensitive in this text. It would pass through in all modes.
                  </p>
                </div>
              </div>
            ) : (
              <div className={`flex items-start gap-3 border p-4 ${
                result.summary.max_severity === "critical"
                  ? "border-red-500/40 bg-red-500/10"
                  : result.summary.max_severity === "high"
                  ? "border-orange-500/40 bg-orange-500/10"
                  : result.summary.max_severity === "medium"
                  ? "border-yellow-500/40 bg-yellow-500/10"
                  : "border-blue-500/40 bg-blue-500/10"
              }`}>
                <AlertTriangle className={`h-6 w-6 shrink-0 mt-0.5 ${
                  result.summary.max_severity === "critical" ? "text-red-400"
                  : result.summary.max_severity === "high" ? "text-orange-400"
                  : result.summary.max_severity === "medium" ? "text-yellow-400"
                  : "text-blue-400"
                }`} />
                <div>
                  <p className="font-mono font-semibold">
                    {result.summary.total} finding{result.summary.total > 1 ? "s" : ""} detected
                    {result.summary.max_severity && (
                      <span className="ml-2"><SeverityBadge severity={result.summary.max_severity} /></span>
                    )}
                  </p>
                  <p className="text-sm text-muted-foreground mt-0.5">
                    Layers fired: {result.summary.categories.map(c => CATEGORY_LABELS[c] ?? c).join(", ")}
                  </p>
                </div>
              </div>
            )}

            {/* Findings list */}
            {result.findings.length > 0 && (
              <div className="space-y-3">
                <h2 className="text-sm font-mono font-semibold uppercase tracking-widest text-muted-foreground">
                  Findings
                </h2>
                {SEVERITY_ORDER.map((sev) =>
                  result.findings
                    .filter((f) => f.severity === sev)
                    .map((f) => <FindingCard key={f.finding_id} finding={f} />)
                )}
              </div>
            )}

            {/* Mode outcomes */}
            <div className="space-y-3">
              <h2 className="text-sm font-mono font-semibold uppercase tracking-widest text-muted-foreground">
                What each mode would do
              </h2>
              <div className="grid grid-cols-1 sm:grid-cols-2 gap-3">
                {MODE_META.map((m) => (
                  <div key={m.key} className="border border-white/10 bg-white/5 p-4 space-y-2">
                    <div className="flex items-center gap-2">
                      {m.icon}
                      <code className="text-xs font-mono text-foreground">{m.label}</code>
                      <ChevronRight className="h-3 w-3 text-muted-foreground/40" />
                      <span className="text-xs text-muted-foreground">{m.desc}</span>
                    </div>
                    <p className="text-sm text-foreground/90 font-mono">
                      {result.mode_outcomes[m.key]}
                    </p>
                  </div>
                ))}
              </div>
            </div>

            {/* CTA */}
            <div className="border border-primary/20 bg-primary/5 p-6 flex flex-col sm:flex-row items-start sm:items-center gap-4">
              <Shield className="h-8 w-8 text-primary shrink-0" />
              <div className="flex-1">
                <p className="font-mono font-semibold text-foreground">Add this protection to your codebase in 30 seconds.</p>
                <code className="text-sm text-primary">pip install killswitch &amp;&amp; killswitch init</code>
              </div>
              <a href="/quickstart" className="shrink-0">
                <Button size="sm" className="font-mono">Get started →</Button>
              </a>
            </div>
          </div>
        )}
      </main>

      <Footer />
    </div>
  );
}
