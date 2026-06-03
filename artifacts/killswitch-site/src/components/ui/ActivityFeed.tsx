import React, { useEffect, useRef, useState } from "react";
import { useGetRecentTelemetry } from "@workspace/api-client-react";
import { ShieldBan, ShieldAlert, ShieldCheck, Eye, Activity } from "lucide-react";

const FINDING_TYPE_LABELS: Record<string, string> = {
  aws_key: "AWS key",
  aws_access_key: "AWS key",
  github_token: "GitHub token",
  generic_api_key: "API key",
  api_key: "API key",
  private_key: "private key",
  pii: "PII",
  email: "email address",
  phone_number: "phone number",
  credit_card: "credit card",
  ssn: "SSN",
  password: "password",
  secret: "secret",
  generic_secret: "secret",
  jwt: "JWT token",
  slack_token: "Slack token",
  stripe_key: "Stripe key",
  gcp_key: "GCP key",
  azure_key: "Azure key",
};

const MODE_CONFIG: Record<string, { label: string; verb: string; color: string; Icon: React.ElementType }> = {
  kill: {
    label: "kill",
    verb: "blocked",
    color: "text-red-400",
    Icon: ShieldBan,
  },
  redact: {
    label: "redact",
    verb: "redacted",
    color: "text-primary",
    Icon: ShieldCheck,
  },
  pause: {
    label: "pause",
    verb: "flagged",
    color: "text-yellow-400",
    Icon: ShieldAlert,
  },
  report_only: {
    label: "report_only",
    verb: "logged",
    color: "text-muted-foreground",
    Icon: Eye,
  },
};

function timeAgo(dateStr: string): string {
  const diff = Math.floor((Date.now() - new Date(dateStr).getTime()) / 1000);
  if (diff < 60) return `${diff}s ago`;
  if (diff < 3600) return `${Math.floor(diff / 60)}m ago`;
  if (diff < 86400) return `${Math.floor(diff / 3600)}h ago`;
  return `${Math.floor(diff / 86400)}d ago`;
}

function formatFindingType(raw: string): string {
  return FINDING_TYPE_LABELS[raw] ?? raw.replace(/_/g, " ");
}

interface FeedEvent {
  finding_type: string;
  mode: string;
  reported_at: string;
}

function EventCard({ event }: { event: FeedEvent }) {
  const cfg = MODE_CONFIG[event.mode] ?? MODE_CONFIG["report_only"];
  const { Icon, color, verb } = cfg;
  const label = formatFindingType(event.finding_type);

  return (
    <div className="flex items-center gap-3 px-4 py-2.5 border-b border-white/5 hover:bg-white/[0.02] transition-colors">
      <Icon className={`h-4 w-4 shrink-0 ${color}`} />
      <span className="text-sm text-foreground flex-1 min-w-0 truncate">
        <span className="font-mono text-xs text-muted-foreground mr-1.5 uppercase tracking-wider">{verb}</span>
        <span className="font-medium">{label}</span>
      </span>
      <span className="text-xs text-muted-foreground/60 font-mono shrink-0">{timeAgo(event.reported_at)}</span>
    </div>
  );
}

const PLACEHOLDER_EVENTS: FeedEvent[] = [
  { finding_type: "aws_key", mode: "kill", reported_at: new Date(Date.now() - 90000).toISOString() },
  { finding_type: "pii", mode: "redact", reported_at: new Date(Date.now() - 240000).toISOString() },
  { finding_type: "github_token", mode: "kill", reported_at: new Date(Date.now() - 480000).toISOString() },
  { finding_type: "generic_api_key", mode: "redact", reported_at: new Date(Date.now() - 900000).toISOString() },
  { finding_type: "jwt", mode: "report_only", reported_at: new Date(Date.now() - 1500000).toISOString() },
  { finding_type: "private_key", mode: "kill", reported_at: new Date(Date.now() - 2400000).toISOString() },
];

export function ActivityFeed() {
  const { data, isLoading } = useGetRecentTelemetry(
    { limit: 20 },
    { query: { refetchInterval: 30_000, staleTime: 20_000 } }
  );

  const events: FeedEvent[] =
    !isLoading && data && data.events.length > 0 ? data.events : PLACEHOLDER_EVENTS;

  const isEmpty = !isLoading && data && data.events.length === 0;
  const showingPlaceholder = isEmpty || isLoading;

  const listRef = useRef<HTMLDivElement>(null);
  const [tick, setTick] = useState(0);

  useEffect(() => {
    const id = setInterval(() => setTick((t) => t + 1), 30_000);
    return () => clearInterval(id);
  }, []);

  return (
    <section className="py-16 relative z-10">
      <div className="container mx-auto px-4 md:px-6">
        <div className="max-w-2xl mx-auto">
          <div className="flex items-center justify-between mb-6">
            <div className="flex items-center gap-2">
              <Activity className="h-5 w-5 text-primary" />
              <h2 className="text-lg font-bold font-mono uppercase tracking-widest text-foreground">
                Live Threat Feed
              </h2>
            </div>
            <div className="flex items-center gap-2">
              <span className="relative flex h-2 w-2">
                <span className="animate-ping absolute inline-flex h-full w-full rounded-full bg-primary opacity-75"></span>
                <span className="relative inline-flex rounded-full h-2 w-2 bg-primary"></span>
              </span>
              <span className="text-xs text-muted-foreground font-mono">
                {showingPlaceholder ? "example data" : "live"}
              </span>
            </div>
          </div>

          <div
            className="bg-card/40 border border-white/10 rounded-xl overflow-hidden backdrop-blur-sm"
            ref={listRef}
          >
            <div className="px-4 py-2 border-b border-white/10 bg-white/[0.02] flex items-center gap-3">
              <span className="text-xs font-mono text-muted-foreground uppercase tracking-widest">
                Recent detections — anonymized
              </span>
            </div>

            {isLoading ? (
              <div className="divide-y divide-white/5">
                {Array.from({ length: 6 }).map((_, i) => (
                  <div key={i} className="flex items-center gap-3 px-4 py-2.5">
                    <div className="h-4 w-4 rounded bg-white/10 animate-pulse shrink-0" />
                    <div className="h-3 flex-1 rounded bg-white/10 animate-pulse" style={{ width: `${55 + (i * 7) % 30}%` }} />
                    <div className="h-3 w-10 rounded bg-white/10 animate-pulse shrink-0" />
                  </div>
                ))}
              </div>
            ) : (
              <div className="divide-y divide-white/5 max-h-[360px] overflow-y-auto scrollbar-thin">
                {events.map((ev, i) => (
                  <EventCard key={`${ev.finding_type}-${ev.reported_at}-${i}`} event={ev} />
                ))}
              </div>
            )}

            {showingPlaceholder && !isLoading && (
              <div className="px-4 py-2 border-t border-white/10 bg-white/[0.02]">
                <p className="text-xs text-muted-foreground/60 font-mono text-center">
                  Showing example data — real events appear as users report telemetry
                </p>
              </div>
            )}
          </div>
        </div>
      </div>
    </section>
  );
}
