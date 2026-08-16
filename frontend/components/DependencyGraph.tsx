"use client";

import React, { useMemo, useState } from "react";
import type { DependencyItem, ObservationResponse } from "@/lib/api";

interface DependencyGraphProps {
  dependencies: DependencyItem[];
  targetUrl: string;
  evidence: ObservationResponse[];
}

export default function DependencyGraph({ dependencies, targetUrl, evidence }: DependencyGraphProps) {
  const [selectedCategory, setSelectedCategory] = useState<string>("ALL");
  const [searchQuery, setSearchQuery] = useState<string>("");
  const [selectedDomain, setSelectedDomain] = useState<DependencyItem | null>(null);
  const [zoomLevel, setZoomLevel] = useState<number>(1);

  // Extract unique categories
  const categories = useMemo(() => {
    const set = new Set<string>();
    dependencies.forEach((dep) => set.add(dep.category));
    return ["ALL", ...Array.from(set)];
  }, [dependencies]);

  // Filter dependencies
  const filteredDependencies = useMemo(() => {
    return dependencies.filter((dep) => {
      const categoryMatch = selectedCategory === "ALL" || dep.category === selectedCategory;
      const searchMatch = searchQuery === "" || dep.domain.toLowerCase().includes(searchQuery.toLowerCase());
      return categoryMatch && searchMatch;
    });
  }, [dependencies, selectedCategory, searchQuery]);

  // Group dependencies by category for node layout
  const groupedByCategory = useMemo(() => {
    const groups: Record<string, DependencyItem[]> = {};
    filteredDependencies.forEach((dep) => {
      groups[dep.category] = groups[dep.category] || [];
      groups[dep.category].push(dep);
    });
    return groups;
  }, [filteredDependencies]);

  const categoryNames = Object.keys(groupedByCategory);

  // Helper colors
  const getCategoryColor = (cat: string) => {
    switch (cat.toLowerCase()) {
      case "analytics":
        return { bg: "bg-cyan-500/10", border: "border-cyan-500/30", text: "text-cyan-400", dot: "#06b6d4" };
      case "cdn":
        return { bg: "bg-purple-500/10", border: "border-purple-500/30", text: "text-purple-400", dot: "#a855f7" };
      case "fonts":
        return { bg: "bg-amber-500/10", border: "border-amber-500/30", text: "text-amber-400", dot: "#f59e0b" };
      case "advertising":
        return { bg: "bg-rose-500/10", border: "border-rose-500/30", text: "text-rose-400", dot: "#f43f5e" };
      default:
        return { bg: "bg-emerald-500/10", border: "border-emerald-500/30", text: "text-emerald-400", dot: "#10b981" };
    }
  };

  // Find linked evidence for selected domain
  const selectedDomainEvidence = useMemo(() => {
    if (!selectedDomain) return [];
    return evidence.filter(
      (ev) => ev.subject.toLowerCase() === selectedDomain.domain.toLowerCase() || ev.observation.toLowerCase().includes(selectedDomain.domain.toLowerCase())
    );
  }, [selectedDomain, evidence]);

  return (
    <div className="bg-[#0b1714] border border-emerald-900/30 rounded-2xl p-6 space-y-6">
      {/* Top Header & Controls */}
      <div className="flex flex-wrap items-center justify-between gap-4 border-b border-emerald-900/20 pb-4">
        <div>
          <h3 className="text-lg font-semibold text-emerald-400 flex items-center gap-2">
            <span>🌐</span> Interactive Dependency Graph
          </h3>
          <p className="text-xs text-emerald-200/60 mt-1">
            Visualizing observed external domains and categorized services for {targetUrl}
          </p>
        </div>

        {/* Controls */}
        <div className="flex items-center gap-3">
          {/* Search Box */}
          <div className="relative">
            <input
              type="text"
              placeholder="Search external domain..."
              value={searchQuery}
              onChange={(e) => setSearchQuery(e.target.value)}
              className="bg-[#060c0a] border border-emerald-900/40 rounded-lg px-3 py-1.5 text-xs text-emerald-200 placeholder-emerald-800 focus:outline-none focus:border-emerald-500 w-48"
            />
            {searchQuery && (
              <button
                onClick={() => setSearchQuery("")}
                className="absolute right-2 top-1.5 text-emerald-600 hover:text-emerald-400 text-xs"
              >
                ✕
              </button>
            )}
          </div>

          {/* Zoom Buttons */}
          <div className="flex items-center bg-[#060c0a] border border-emerald-900/40 rounded-lg p-1 text-xs">
            <button
              onClick={() => setZoomLevel((z) => Math.max(0.6, z - 0.1))}
              className="px-2 py-0.5 text-emerald-400 hover:bg-emerald-900/30 rounded font-bold"
              title="Zoom Out"
            >
              −
            </button>
            <span className="px-2 text-emerald-400/70 font-mono text-[10px]">{Math.round(zoomLevel * 100)}%</span>
            <button
              onClick={() => setZoomLevel((z) => Math.min(1.6, z + 0.1))}
              className="px-2 py-0.5 text-emerald-400 hover:bg-emerald-900/30 rounded font-bold"
              title="Zoom In"
            >
              +
            </button>
            <button
              onClick={() => setZoomLevel(1)}
              className="ml-1 px-1.5 py-0.5 text-emerald-500 hover:text-emerald-300 text-[10px]"
              title="Reset Zoom"
            >
              Reset
            </button>
          </div>
        </div>
      </div>

      {/* Category Filter Pills */}
      <div className="flex items-center gap-2 overflow-x-auto pb-1 text-xs">
        <span className="text-emerald-400/50 text-[11px] uppercase font-mono tracking-wider">Filter:</span>
        {categories.map((cat) => (
          <button
            key={cat}
            onClick={() => setSelectedCategory(cat)}
            className={`px-3 py-1 rounded-full border text-xs transition-colors whitespace-nowrap ${
              selectedCategory === cat
                ? "bg-emerald-500/20 text-emerald-300 border-emerald-500/40 font-medium"
                : "bg-emerald-950/30 text-emerald-400/60 border-emerald-900/20 hover:text-emerald-300 hover:border-emerald-800"
            }`}
          >
            {cat}
          </button>
        ))}
      </div>

      {/* Main Content Area: Graph Canvas + Inspection Drawer */}
      <div className="grid grid-cols-1 lg:grid-cols-3 gap-6">
        {/* Graph Canvas Container */}
        <div className={`relative bg-[#050b09] border border-emerald-950 rounded-xl p-6 overflow-hidden min-h-[420px] flex items-center justify-center ${selectedDomain ? "lg:col-span-2" : "lg:col-span-3"}`}>
          {filteredDependencies.length === 0 ? (
            <div className="text-center text-emerald-400/50 py-12">
              <p className="text-sm">No external dependencies matched your query.</p>
            </div>
          ) : (
            <div
              className="w-full transition-transform duration-200"
              style={{ transform: `scale(${zoomLevel})`, transformOrigin: "center center" }}
            >
              {/* Central Website Root Node */}
              <div className="flex flex-col items-center mb-8">
                <div className="bg-emerald-500/20 border border-emerald-500/50 px-4 py-2 rounded-xl text-center shadow-lg shadow-emerald-950">
                  <div className="text-[10px] text-emerald-400/70 font-mono uppercase tracking-widest">Target Origin</div>
                  <div className="text-sm font-semibold text-emerald-200 font-mono">{targetUrl}</div>
                </div>
                <div className="h-6 w-0.5 bg-gradient-to-b from-emerald-500/50 to-emerald-900/30" />
              </div>

              {/* Category Clusters */}
              <div className="grid grid-cols-1 md:grid-cols-2 xl:grid-cols-3 gap-6">
                {categoryNames.map((catName) => {
                  const depsInCat = groupedByCategory[catName];
                  const style = getCategoryColor(catName);
                  return (
                    <div
                      key={catName}
                      className={`${style.bg} border ${style.border} rounded-xl p-4 space-y-3`}
                    >
                      <div className="flex items-center justify-between border-b border-emerald-900/20 pb-2">
                        <span className={`text-xs font-semibold ${style.text} flex items-center gap-1.5`}>
                          <span className="h-2 w-2 rounded-full" style={{ backgroundColor: style.dot }} />
                          {catName}
                        </span>
                        <span className="text-[10px] font-mono text-emerald-400/50 bg-emerald-950/60 px-2 py-0.5 rounded">
                          {depsInCat.length} {depsInCat.length === 1 ? "domain" : "domains"}
                        </span>
                      </div>

                      {/* Domain Nodes */}
                      <div className="space-y-2">
                        {depsInCat.map((dep) => {
                          const isSelected = selectedDomain?.id === dep.id;
                          return (
                            <div
                              key={dep.id}
                              onClick={() => setSelectedDomain(dep)}
                              className={`cursor-pointer p-2.5 rounded-lg border transition-all text-xs flex items-center justify-between ${
                                isSelected
                                  ? "bg-emerald-500/20 border-emerald-400 text-emerald-100 ring-1 ring-emerald-400/50"
                                  : "bg-[#08120e] border-emerald-900/30 text-emerald-200/90 hover:border-emerald-600/50 hover:bg-[#0c1a14]"
                              }`}
                            >
                              <div className="truncate pr-2 font-mono text-[11px]">{dep.domain}</div>
                              <div className="flex items-center gap-1.5 shrink-0">
                                <span className="text-[10px] text-emerald-400/60 bg-emerald-950 px-1.5 py-0.5 rounded">
                                  {dep.reference_count} ref{dep.reference_count > 1 ? "s" : ""}
                                </span>
                              </div>
                            </div>
                          );
                        })}
                      </div>
                    </div>
                  );
                })}
              </div>
            </div>
          )}
        </div>

        {/* Click-to-Inspect Side Panel */}
        {selectedDomain && (
          <div className="bg-[#050b09] border border-emerald-800/40 rounded-xl p-5 space-y-5 lg:col-span-1">
            <div className="flex items-start justify-between border-b border-emerald-900/30 pb-3">
              <div>
                <span className="text-[10px] font-mono text-emerald-500 uppercase tracking-widest">Selected Dependency</span>
                <h4 className="text-sm font-bold text-emerald-200 font-mono break-all">{selectedDomain.domain}</h4>
              </div>
              <button
                onClick={() => setSelectedDomain(null)}
                className="text-emerald-600 hover:text-emerald-300 text-xs px-2 py-1 bg-emerald-950 rounded"
              >
                Close ✕
              </button>
            </div>

            {/* Metadata Badge Grid */}
            <div className="grid grid-cols-2 gap-3 text-xs">
              <div className="bg-[#08120e] p-2.5 rounded-lg border border-emerald-900/20">
                <div className="text-[10px] text-emerald-400/60">Category</div>
                <div className="font-semibold text-emerald-300 mt-0.5">{selectedDomain.category}</div>
              </div>
              <div className="bg-[#08120e] p-2.5 rounded-lg border border-emerald-900/20">
                <div className="text-[10px] text-emerald-400/60">Confidence</div>
                <div className="font-semibold text-emerald-300 mt-0.5">
                  {Math.round(selectedDomain.confidence * 100)}% (🟡 INFERRED)
                </div>
              </div>
              <div className="bg-[#08120e] p-2.5 rounded-lg border border-emerald-900/20">
                <div className="text-[10px] text-emerald-400/60">References</div>
                <div className="font-semibold text-emerald-300 mt-0.5">{selectedDomain.reference_count} times</div>
              </div>
              <div className="bg-[#08120e] p-2.5 rounded-lg border border-emerald-900/20">
                <div className="text-[10px] text-emerald-400/60">Classification</div>
                <div className="font-semibold text-emerald-400 mt-0.5 uppercase text-[10px]">
                  {selectedDomain.classification}
                </div>
              </div>
            </div>

            {/* Sample Resource URLs */}
            {selectedDomain.sample_resource_urls && selectedDomain.sample_resource_urls.length > 0 && (
              <div className="space-y-2">
                <div className="text-[11px] font-semibold text-emerald-400/80">Sample Referenced Resources</div>
                <ul className="space-y-1 max-h-36 overflow-y-auto pr-1">
                  {selectedDomain.sample_resource_urls.map((url, idx) => (
                    <li key={idx} className="text-[11px] font-mono text-emerald-300/70 bg-[#08120e] p-1.5 rounded border border-emerald-900/20 truncate" title={url}>
                      {url}
                    </li>
                  ))}
                </ul>
              </div>
            )}

            {/* Linked Evidence */}
            <div className="space-y-2 border-t border-emerald-900/30 pt-3">
              <div className="text-[11px] font-semibold text-emerald-400/80 flex items-center justify-between">
                <span>Verified Observations & Evidence</span>
                <span className="text-[10px] font-mono text-emerald-500/70">{selectedDomainEvidence.length} items</span>
              </div>
              {selectedDomainEvidence.length === 0 ? (
                <p className="text-xs text-emerald-400/40 italic">Derived from structural resource observations.</p>
              ) : (
                <div className="space-y-2 max-h-48 overflow-y-auto pr-1">
                  {selectedDomainEvidence.map((ev) => (
                    <div key={ev.id} className="bg-[#08120e] p-2 rounded border border-emerald-900/30 text-[11px] space-y-1">
                      <div className="flex items-center justify-between text-[10px] text-emerald-500">
                        <span className="font-mono">{ev.category}</span>
                        <span className="text-emerald-400/60">{ev.classification}</span>
                      </div>
                      <p className="text-emerald-200/80">{ev.observation}</p>
                    </div>
                  ))}
                </div>
              )}
            </div>
          </div>
        )}
      </div>
    </div>
  );
}
