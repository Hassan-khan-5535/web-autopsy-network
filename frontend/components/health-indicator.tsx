"use client";

import { useEffect, useState } from "react";
import { getHealth, type HealthResponse } from "@/lib/api";

type LoadState = "loading" | "healthy" | "unavailable";

export function HealthIndicator() {
  const [state, setState] = useState<LoadState>("loading");
  const [health, setHealth] = useState<HealthResponse | null>(null);

  useEffect(() => {
    let mounted = true;
    void getHealth()
      .then((response) => {
        if (!mounted) return;
        setHealth(response);
        setState("healthy");
      })
      .catch(() => {
        if (mounted) setState("unavailable");
      });
    return () => { mounted = false; };
  }, []);

  const statusCopy = state === "healthy"
    ? `Backend reachable · database ${health?.database ?? "unknown"}`
    : state === "unavailable"
      ? "Backend unavailable · start the local compose stack"
      : "Checking backend health…";

  const statusClass = state === "healthy" ? "bg-emerald-300" : state === "unavailable" ? "bg-amber-300" : "bg-sky-300 animate-pulse";

  return (
    <div className="flex max-w-xl items-center gap-3 rounded-2xl border border-white/10 bg-black/20 px-4 py-4 backdrop-blur-sm">
      <span className={`h-2.5 w-2.5 rounded-full ${statusClass}`} aria-hidden="true" />
      <div>
        <p className="font-mono text-xs text-emerald-50/80">CONTROL PLANE</p>
        <p className="mt-1 text-sm text-emerald-50/60" aria-live="polite">{statusCopy}</p>
      </div>
    </div>
  );
}
