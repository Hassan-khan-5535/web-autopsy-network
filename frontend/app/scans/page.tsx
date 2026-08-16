"use client";

import Link from "next/link";
import { useState } from "react";
import { useRouter } from "next/navigation";
import { createScan } from "@/lib/api";

export default function NewScanPage() {
  const [url, setUrl] = useState("");
  const [maxDepth, setMaxDepth] = useState("2");
  const [maxPages, setMaxPages] = useState("30");
  const [acknowledged, setAcknowledged] = useState(false);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const router = useRouter();

  const handleSubmit = async (e: React.FormEvent) => {
    e.preventDefault();
    if (!acknowledged) {
      setError("You must acknowledge authorization to scan this target.");
      return;
    }

    setError(null);
    setLoading(true);

    try {
      const scan = await createScan(url, acknowledged, {
        max_depth: Number(maxDepth),
        max_pages: Number(maxPages),
      });
      router.push(`/scans/${scan.id}`);
    } catch (err: unknown) {
      setError(err instanceof Error ? err.message : "An unexpected error occurred.");
      setLoading(false);
    }
  };

  return (
    <main className="min-h-screen bg-[#08110f] text-[#ecf4ee] px-6 py-12 sm:px-10">
      <div className="max-w-2xl mx-auto">
        <header className="mb-10">
          <h1 className="text-3xl font-semibold tracking-tight sm:text-4xl">New Autopsy Scan</h1>
          <p className="mt-3 text-emerald-100/60 text-lg">Enter a public URL to begin bounded evidence collection.</p>
        </header>

        <form onSubmit={handleSubmit} className="space-y-6 bg-black/20 p-8 rounded-2xl border border-white/5">
          <div>
            <label htmlFor="url" className="block text-sm font-medium text-emerald-100/80 mb-2">Target URL</label>
            <input
              id="url"
              type="url"
              required
              placeholder="https://example.com"
              value={url}
              onChange={(e) => setUrl(e.target.value)}
              className="w-full bg-[#0d1a17] border border-emerald-500/20 rounded-lg px-4 py-3 text-emerald-50 focus:outline-none focus:ring-2 focus:ring-emerald-500/50"
            />
          </div>

          <div className="grid gap-4 sm:grid-cols-2">
            <div>
              <label htmlFor="max-depth" className="block text-sm font-medium text-emerald-100/80 mb-2">Max crawl depth</label>
              <input
                id="max-depth"
                type="number"
                min="0"
                max="5"
                value={maxDepth}
                onChange={(e) => setMaxDepth(e.target.value)}
                className="w-full bg-[#0d1a17] border border-emerald-500/20 rounded-lg px-4 py-3 text-emerald-50 focus:outline-none focus:ring-2 focus:ring-emerald-500/50"
              />
            </div>
            <div>
              <label htmlFor="max-pages" className="block text-sm font-medium text-emerald-100/80 mb-2">Max pages</label>
              <input
                id="max-pages"
                type="number"
                min="1"
                max="100"
                value={maxPages}
                onChange={(e) => setMaxPages(e.target.value)}
                className="w-full bg-[#0d1a17] border border-emerald-500/20 rounded-lg px-4 py-3 text-emerald-50 focus:outline-none focus:ring-2 focus:ring-emerald-500/50"
              />
            </div>
          </div>
          <p className="-mt-3 text-xs text-emerald-100/45">The server always enforces hard safety ceilings, hostname-only crawling, robots.txt rules, concurrency limits, and a request delay.</p>

          <div className="flex items-start gap-3">
            <input
              id="auth"
              type="checkbox"
              checked={acknowledged}
              onChange={(e) => setAcknowledged(e.target.checked)}
              className="mt-1 h-4 w-4 rounded border-emerald-500/30 bg-[#0d1a17] text-emerald-500 focus:ring-emerald-500 focus:ring-offset-[#08110f]"
            />
            <label htmlFor="auth" className="text-sm text-emerald-100/70">
              I confirm that I am authorized to scan this target or that it is a publicly accessible website permissible to scan under standard terms.
            </label>
          </div>

          {error && (
            <div className="p-4 bg-red-500/10 border border-red-500/20 rounded-lg text-red-400 text-sm">
              {error}
            </div>
          )}

          <div className="pt-4 flex items-center justify-between">
            <Link href="/" className="text-sm text-emerald-500 hover:text-emerald-400 transition-colors">
              &larr; Back to Home
            </Link>
            <button
              type="submit"
              disabled={loading}
              className="inline-flex h-11 items-center justify-center rounded-lg bg-emerald-500 px-6 text-sm font-medium text-emerald-950 transition-colors hover:bg-emerald-400 focus:outline-none focus:ring-2 focus:ring-emerald-400 focus:ring-offset-2 focus:ring-offset-[#08110f] disabled:opacity-50 disabled:cursor-not-allowed"
            >
              {loading ? "Crawling..." : "Start Collection"}
            </button>
          </div>
        </form>
      </div>
    </main>
  );
}
