import React, { useEffect, useRef, useState } from "react";
import { useInView } from "framer-motion";
import { useGetTelemetryStats } from "@workspace/api-client-react";

function useCountUp(target: number, duration = 1800, enabled = true) {
  const [count, setCount] = useState(0);
  const rafRef = useRef<number | null>(null);

  useEffect(() => {
    if (!enabled || target === 0) {
      setCount(target);
      return;
    }

    const start = performance.now();

    function tick(now: number) {
      const elapsed = now - start;
      const progress = Math.min(elapsed / duration, 1);
      const eased = 1 - Math.pow(1 - progress, 4);
      setCount(Math.round(target * eased));

      if (progress < 1) {
        rafRef.current = requestAnimationFrame(tick);
      }
    }

    rafRef.current = requestAnimationFrame(tick);
    return () => {
      if (rafRef.current !== null) cancelAnimationFrame(rafRef.current);
    };
  }, [target, duration, enabled]);

  return count;
}

function formatNumber(n: number): string {
  if (n >= 1_000_000) return (n / 1_000_000).toFixed(1).replace(/\.0$/, "") + "M";
  if (n >= 1_000) return (n / 1_000).toFixed(1).replace(/\.0$/, "") + "k";
  return n.toLocaleString();
}

interface StatItemProps {
  value: number;
  label: string;
  animate: boolean;
  loading?: boolean;
}

function StatItem({ value, label, animate, loading }: StatItemProps) {
  const count = useCountUp(value, 1800, animate && !loading);

  return (
    <div className="flex flex-col items-center gap-1 px-6 py-4">
      <span className="font-display text-4xl md:text-5xl font-bold text-primary tabular-nums">
        {loading ? (
          <span className="inline-block w-20 h-10 bg-white/10 animate-pulse rounded" />
        ) : (
          formatNumber(count)
        )}
      </span>
      <span className="text-xs md:text-sm text-muted-foreground uppercase tracking-widest font-mono text-center">
        {label}
      </span>
    </div>
  );
}

export function StatsBar() {
  const ref = useRef<HTMLDivElement>(null);
  const isInView = useInView(ref, { once: true, margin: "-60px" });

  const { data: telemetry, isLoading } = useGetTelemetryStats({
    query: { staleTime: 5 * 60 * 1000 } as any,
  });

  const threatsBlocked =
    (telemetry?.total_prohibited_stopped ?? 0) +
    (telemetry?.total_sensitive_stopped ?? 0);

  return (
    <div ref={ref} className="border-y border-white/10 bg-card/30 backdrop-blur-sm relative z-10">
      <div className="container mx-auto px-4 md:px-6">
        <div className="grid grid-cols-2 divide-x divide-white/10">
          <StatItem
            value={telemetry?.total_commands_analyzed ?? 0}
            label="LLM calls scanned"
            animate={isInView}
            loading={isLoading}
          />
          <StatItem
            value={threatsBlocked}
            label="Threats blocked"
            animate={isInView}
            loading={isLoading}
          />
        </div>
      </div>
    </div>
  );
}
