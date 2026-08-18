"use client";

import { useState } from "react";
import Link from "next/link";

type SystemNode = {
  id: string;
  name: string;
  category: "GATEWAY" | "WORKER" | "ENGINE" | "STORAGE";
  description: string;
  details: string[];
  queue?: string;
  isolation?: string;
};

const SYSTEM_NODES: SystemNode[] = [
  {
    id: "admission",
    name: "URL Admission Guard",
    category: "GATEWAY",
    description: "Enforces SSRF protection, socket-level IP connection hooks, and RFC1918/DNS-rebinding checks before any network request is allowed.",
    details: [
      "Validates target scheme (HTTP/HTTPS only)",
      "Socket-level IP connection validation (connect hook)",
      "Blocks IPv4/IPv6 private ranges, loopback, and cloud metadata 169.254.169.254",
      "Hop-by-hop redirect URL re-verification",
    ],
  },
  {
    id: "worker-crawl",
    name: "Crawl Worker Pool",
    category: "WORKER",
    queue: "crawl",
    description: "Executes same-domain bounded HTTP crawling with configurable depth, page ceiling, and politeness rate delays.",
    details: [
      "Queue: crawl",
      "I/O-bound concurrency control",
      "Same-domain policy enforcement (registrable or exact host)",
      "Normalizes canonical URLs and query strings",
    ],
  },
  {
    id: "worker-browser",
    name: "Playwright Sandbox Worker",
    category: "WORKER",
    queue: "browser",
    isolation: "Container Sandbox (512MB RAM, unprivileged user)",
    description: "Runs dynamic JavaScript rendering and DOM extraction inside an isolated, non-root Chromium Playwright container.",
    details: [
      "Queue: browser",
      "Flags: --no-sandbox, --disable-setuid-sandbox, --disable-local-file-access",
      "Playwright route interceptor aborting internal IP sub-resources",
      "Per-page execution budget: 30s timeout",
    ],
  },
  {
    id: "worker-analysis",
    name: "Deterministic Analysis Engine Pool",
    category: "ENGINE",
    queue: "analysis",
    description: "Executes parallel deterministic algorithms for technology DNA, security headers, performance metrics, WCAG accessibility, and structure.",
    details: [
      "Queue: analysis",
      "Zero network requests (operates on stored evidence)",
      "Categorizes findings as OBSERVED or INFERRED",
      "Generates structured security & performance risk matrices",
    ],
  },
  {
    id: "worker-ai",
    name: "LLM Citation Gate & AI Doctor",
    category: "ENGINE",
    queue: "ai",
    description: "Generates executive summaries and interactive Q&A strictly citation-grounded to validated evidence IDs.",
    details: [
      "Queue: ai",
      "Wraps untrusted page content in <untrusted_scanned_content> XML tags",
      "Hardened citation validator: strips ungrounded claims with [UNGROUNDED_CLAIM_REJECTED]",
      "Rate-limited user Q&A (5 req/min per IP)",
    ],
  },
  {
    id: "diagnosis-engine",
    name: "Cause of Death Engine",
    category: "ENGINE",
    description: "Computes non-literal diagnostic root cause summary and impact score based on dominant findings.",
    details: [
      "Multi-dimensional severity rubric",
      "Dominant bottleneck selection algorithm",
      "Generates branded diagnosis card with mandatory disclaimer",
    ],
  },
  {
    id: "storage",
    name: "PostgreSQL & Redis Storage Layer",
    category: "STORAGE",
    description: "Persists scan states, agent tasks, HTTP responses, composite evidence indexes, and Redis-backed report cache.",
    details: [
      "SQLAlchemy ORM with eager loading (selectinload) eliminating N+1 queries",
      "Alembic database migrations",
      "Redis response cache for completed scans (1h TTL)",
      "Celery task state transport & idempotent task creation",
    ],
  },
];

export default function SystemArchitecturePage() {
  const [selectedNode, setSelectedNode] = useState<SystemNode>(SYSTEM_NODES[0]);

  return (
    <main className="min-h-screen bg-[#08110f] text-[#ecf4ee] px-6 py-10 sm:px-10">
      <div className="max-w-6xl mx-auto space-y-8">
        {/* Header */}
        <header className="flex items-center justify-between border-b border-emerald-100/10 pb-6">
          <div>
            <div className="flex items-center gap-3 mb-2">
              <span className="font-mono text-xs text-emerald-400 bg-emerald-500/10 border border-emerald-500/20 px-2.5 py-1 rounded">
                PLATFORM ARCHITECTURE
              </span>
              <p className="text-xs text-emerald-100/40 font-mono">Phases 1–15 As-Built</p>
            </div>
            <h1 className="text-3xl font-semibold tracking-tight">System Architecture Map</h1>
            <p className="text-sm text-emerald-100/60 mt-1">
              Explorable interactive map of Web Autopsy Network&apos;s distributed micro-architecture.
            </p>
          </div>
          <Link href="/" className="text-sm text-emerald-400 hover:text-emerald-300 font-medium">
            &larr; Return Home
          </Link>
        </header>

        {/* Distributed Topology Diagram */}
        <div className="grid grid-cols-1 lg:grid-cols-3 gap-8">
          {/* Node Selector List */}
          <div className="lg:col-span-1 space-y-3">
            <h2 className="text-xs font-mono text-emerald-300/80 uppercase tracking-widest px-1">
              Pipeline Components
            </h2>
            {SYSTEM_NODES.map((node) => {
              const isSelected = node.id === selectedNode.id;
              return (
                <button
                  key={node.id}
                  onClick={() => setSelectedNode(node)}
                  className={`w-full text-left p-4 rounded-xl border transition-all ${
                    isSelected
                      ? "bg-emerald-500/15 border-emerald-400 text-emerald-100 shadow-lg shadow-emerald-500/10"
                      : "bg-[#0d1c19] border-emerald-100/10 text-emerald-100/70 hover:border-emerald-500/30 hover:text-emerald-100"
                  }`}
                >
                  <div className="flex items-center justify-between mb-1">
                    <span className="font-mono text-[10px] font-bold px-2 py-0.5 rounded bg-emerald-950 border border-emerald-500/20 text-emerald-300">
                      {node.category}
                    </span>
                    {node.queue && (
                      <span className="font-mono text-[10px] text-amber-300/80">
                        Queue: {node.queue}
                      </span>
                    )}
                  </div>
                  <h3 className="text-sm font-semibold mt-1">{node.name}</h3>
                </button>
              );
            })}
          </div>

          {/* Node Detailed Specification Modal / Card */}
          <div className="lg:col-span-2 bg-[#0c1815] border border-emerald-500/20 rounded-2xl p-6 sm:p-8 space-y-6">
            <div className="flex items-center justify-between border-b border-emerald-100/10 pb-4">
              <div>
                <span className="font-mono text-xs text-emerald-400 font-bold px-2.5 py-1 rounded bg-emerald-500/10 border border-emerald-500/20">
                  {selectedNode.category}
                </span>
                <h2 className="text-2xl font-semibold mt-3">{selectedNode.name}</h2>
              </div>
              {selectedNode.isolation && (
                <div className="text-right">
                  <span className="font-mono text-xs text-amber-300 bg-amber-500/10 border border-amber-500/20 px-2.5 py-1 rounded">
                    ISOLATED SANDBOX
                  </span>
                </div>
              )}
            </div>

            <p className="text-sm text-emerald-100/80 leading-relaxed">
              {selectedNode.description}
            </p>

            <div className="space-y-3 pt-4 border-t border-emerald-100/10">
              <h3 className="font-mono text-xs text-emerald-300 uppercase tracking-wider">
                Technical Safeguards & Specifications
              </h3>
              <ul className="space-y-2">
                {selectedNode.details.map((detail, idx) => (
                  <li key={idx} className="flex items-start gap-2 text-xs text-emerald-100/70 font-mono">
                    <span className="text-emerald-400 font-bold">✓</span>
                    <span>{detail}</span>
                  </li>
                ))}
              </ul>
            </div>

            {/* Visual Pipeline Trace */}
            <div className="mt-8 pt-6 border-t border-emerald-100/10">
              <h3 className="font-mono text-xs text-emerald-300/80 uppercase tracking-wider mb-3">
                Execution Flow Position
              </h3>
              <div className="flex items-center gap-2 overflow-x-auto pb-2 text-[10px] font-mono text-emerald-100/50">
                <span className="px-2 py-1 bg-emerald-950 border border-emerald-500/30 rounded text-emerald-300">
                  Admission
                </span>
                <span>&rarr;</span>
                <span className="px-2 py-1 bg-emerald-950 border border-emerald-500/30 rounded text-emerald-300">
                  HTTP Crawl
                </span>
                <span>&rarr;</span>
                <span className="px-2 py-1 bg-emerald-950 border border-emerald-500/30 rounded text-emerald-300">
                  Browser Worker
                </span>
                <span>&rarr;</span>
                <span className="px-2 py-1 bg-emerald-950 border border-emerald-500/30 rounded text-emerald-300">
                  Deterministic Engines
                </span>
                <span>&rarr;</span>
                <span className="px-2 py-1 bg-emerald-950 border border-emerald-500/30 rounded text-emerald-300">
                  LLM Doctor
                </span>
              </div>
            </div>
          </div>
        </div>
      </div>
    </main>
  );
}
