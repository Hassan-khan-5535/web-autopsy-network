"use client";

import { useMemo, useState } from "react";
import type { AttackSurfaceGraphResponse } from "@/lib/api";

type Props = { graph: AttackSurfaceGraphResponse };

const labelFor = (value: string) => value.replaceAll("_", " ").toLowerCase();

export function AttackSurfaceGraph({ graph }: Props) {
  const [entityFilter, setEntityFilter] = useState("all");
  const [relationshipFilter, setRelationshipFilter] = useState("all");
  const [selectedNodeId, setSelectedNodeId] = useState<string | null>(null);

  const entityTypes = useMemo(() => Object.keys(graph.summary.entity_counts).sort(), [graph]);
  const relationshipTypes = useMemo(() => Object.keys(graph.summary.relationship_counts).sort(), [graph]);
  const visibleNodes = useMemo(
    () => graph.nodes.filter((node) => entityFilter === "all" || node.entity_type === entityFilter),
    [entityFilter, graph.nodes],
  );
  const visibleEdges = useMemo(
    () => graph.edges.filter((edge) => relationshipFilter === "all" || edge.relationship_type === relationshipFilter),
    [graph.edges, relationshipFilter],
  );
  const selectedNode = graph.nodes.find((node) => node.id === selectedNodeId) ?? null;
  const nodeLookup = useMemo(() => new Map(graph.nodes.map((node) => [node.id, node])), [graph.nodes]);

  return (
    <section id="attack-surface-graph" className="space-y-5 rounded-2xl border border-cyan-500/25 bg-[#061415] p-6 shadow-[0_0_45px_rgba(34,211,238,0.06)]">
      <div className="flex flex-col gap-4 border-b border-cyan-400/15 pb-5 lg:flex-row lg:items-start lg:justify-between">
        <div>
          <p className="font-mono text-[11px] uppercase tracking-[0.22em] text-cyan-300/70">Extension 10 · Correlation Agent</p>
          <h2 className="mt-1 text-xl font-semibold text-cyan-200">Attack Surface Graph</h2>
          <p className="mt-2 max-w-3xl text-sm text-emerald-100/55">Evidence-backed associations across discovered assets, services, endpoints, technologies, findings, and review evidence.</p>
        </div>
        <div className="max-w-sm rounded-xl border border-amber-300/20 bg-amber-400/5 px-3 py-2 text-xs leading-relaxed text-amber-100/80">
          <span className="font-mono text-[10px] uppercase tracking-wider text-amber-300">Safety boundary</span>
          <p className="mt-1">Prioritization only. Graph relationships are not exploit paths or proof of exploitability.</p>
        </div>
      </div>

      <div className="grid gap-3 sm:grid-cols-2 xl:grid-cols-4">
        <Metric label="Graph nodes" value={graph.summary.node_count} accent="text-cyan-300" />
        <Metric label="Relationships" value={graph.summary.edge_count} accent="text-emerald-300" />
        <Metric label="Priority reviews" value={graph.summary.priority_path_count} accent="text-amber-300" />
        <Metric label="Correlation version" value={graph.correlation_version} accent="text-fuchsia-300" compact />
      </div>

      <div className="grid gap-3 rounded-xl border border-cyan-500/15 bg-[#041011] p-4 md:grid-cols-2">
        <label className="grid gap-1.5 text-xs font-mono uppercase tracking-wider text-emerald-100/45">
          Entity type
          <select value={entityFilter} onChange={(event) => setEntityFilter(event.target.value)} className="rounded-lg border border-cyan-500/20 bg-[#07191a] px-3 py-2 text-sm normal-case tracking-normal text-cyan-100 outline-none focus:border-cyan-400">
            <option value="all">All entities ({graph.nodes.length})</option>
            {entityTypes.map((type) => <option key={type} value={type}>{type} ({graph.summary.entity_counts[type]})</option>)}
          </select>
        </label>
        <label className="grid gap-1.5 text-xs font-mono uppercase tracking-wider text-emerald-100/45">
          Relationship type
          <select value={relationshipFilter} onChange={(event) => setRelationshipFilter(event.target.value)} className="rounded-lg border border-cyan-500/20 bg-[#07191a] px-3 py-2 text-sm normal-case tracking-normal text-cyan-100 outline-none focus:border-cyan-400">
            <option value="all">All relationships ({graph.edges.length})</option>
            {relationshipTypes.map((type) => <option key={type} value={type}>{labelFor(type)} ({graph.summary.relationship_counts[type]})</option>)}
          </select>
        </label>
      </div>

      {graph.priority_paths.length > 0 && (
        <div className="rounded-xl border border-amber-400/20 bg-amber-400/5 p-4">
          <h3 className="font-mono text-xs uppercase tracking-[0.18em] text-amber-300">Priority review paths</h3>
          <div className="mt-3 space-y-2">
            {graph.priority_paths.slice(0, 5).map((path) => (
              <button key={path.relationship.id} type="button" onClick={() => setSelectedNodeId(path.finding.id)} className="w-full rounded-lg border border-amber-300/15 bg-[#11130e]/50 px-3 py-3 text-left transition hover:border-amber-300/35 hover:bg-amber-300/5">
                <p className="text-sm text-amber-50"><span className="font-medium">{path.finding.label}</span><span className="mx-2 text-amber-300/70">→</span>{path.affected_asset.label}</p>
                <p className="mt-1 text-xs text-amber-100/55">{path.disclaimer}</p>
              </button>
            ))}
          </div>
        </div>
      )}

      <div className="grid gap-4 xl:grid-cols-[1.25fr_0.75fr]">
        <div className="rounded-xl border border-emerald-500/15 bg-[#041011]">
          <div className="flex items-center justify-between border-b border-emerald-500/15 px-4 py-3"><h3 className="font-mono text-xs uppercase tracking-[0.18em] text-emerald-300">Graph inventory</h3><span className="text-xs text-emerald-100/45">{visibleNodes.length} visible</span></div>
          <div className="max-h-[340px] overflow-y-auto p-2">
            {visibleNodes.map((node) => (
              <button key={node.id} type="button" onClick={() => setSelectedNodeId(node.id)} className={`mb-1 flex w-full items-center gap-3 rounded-lg px-3 py-2.5 text-left transition ${selectedNodeId === node.id ? "bg-cyan-400/10 ring-1 ring-cyan-300/35" : "hover:bg-emerald-400/5"}`}>
                <span className="min-w-0 flex-1 truncate text-sm text-emerald-50" title={node.label}>{node.label}</span>
                <span className="rounded border border-cyan-500/20 px-1.5 py-0.5 font-mono text-[10px] text-cyan-200">{node.entity_type}</span>
                <span className="font-mono text-[11px] text-emerald-200/55">{Math.round(node.confidence)}%</span>
              </button>
            ))}
            {visibleNodes.length === 0 && <p className="p-5 text-sm text-emerald-100/45">No nodes match this entity filter.</p>}
          </div>
        </div>

        <aside className="rounded-xl border border-fuchsia-500/15 bg-[#0b0b16] p-4">
          <h3 className="font-mono text-xs uppercase tracking-[0.18em] text-fuchsia-300">Evidence provenance</h3>
          {selectedNode ? (
            <div className="mt-3 space-y-3 text-sm">
              <div><p className="text-fuchsia-100">{selectedNode.label}</p><p className="mt-1 font-mono text-[11px] text-fuchsia-200/55">{selectedNode.entity_type} · {selectedNode.classification} · {Math.round(selectedNode.confidence)}% confidence</p></div>
              <div className="rounded-lg border border-fuchsia-400/15 bg-fuchsia-400/5 p-3"><p className="font-mono text-[10px] uppercase tracking-wider text-fuchsia-300/75">Attributes</p><pre className="mt-2 overflow-auto whitespace-pre-wrap break-words text-xs text-fuchsia-100/75">{JSON.stringify(selectedNode.attributes, null, 2)}</pre></div>
              <div><p className="font-mono text-[10px] uppercase tracking-wider text-fuchsia-300/75">Stored provenance</p><div className="mt-2 space-y-1.5">{selectedNode.provenance.slice(0, 4).map((item, index) => <p key={`${selectedNode.id}-${index}`} className="rounded bg-white/[0.03] px-2 py-1.5 font-mono text-[11px] text-fuchsia-100/65">{String(item.source_type || "source")} · {String(item.source || "stored evidence")}</p>)}</div></div>
            </div>
          ) : <p className="mt-3 text-sm leading-relaxed text-fuchsia-100/50">Select a graph node to review its typed attributes and stored evidence provenance.</p>}
        </aside>
      </div>

      <div className="rounded-xl border border-cyan-500/15 bg-[#041011]">
        <div className="flex items-center justify-between border-b border-cyan-500/15 px-4 py-3"><h3 className="font-mono text-xs uppercase tracking-[0.18em] text-cyan-300">Visible relationships</h3><span className="text-xs text-cyan-100/45">{visibleEdges.length} visible</span></div>
        <div className="max-h-64 overflow-auto divide-y divide-cyan-500/10">
          {visibleEdges.map((edge) => <div key={edge.id} className="grid gap-2 px-4 py-3 text-sm md:grid-cols-[1fr_auto_1fr_auto]"><span className="truncate text-emerald-50" title={nodeLookup.get(edge.source_node_id)?.label}>{nodeLookup.get(edge.source_node_id)?.label || "Unknown node"}</span><span className="font-mono text-[10px] uppercase tracking-wider text-cyan-300">{labelFor(edge.relationship_type)}</span><span className="truncate text-emerald-50" title={nodeLookup.get(edge.target_node_id)?.label}>{nodeLookup.get(edge.target_node_id)?.label || "Unknown node"}</span><span className="font-mono text-xs text-cyan-100/50">{Math.round(edge.confidence)}%</span></div>)}
          {visibleEdges.length === 0 && <p className="p-5 text-sm text-cyan-100/45">No relationships match this filter.</p>}
        </div>
      </div>

      {graph.updates.length > 0 && <p className="text-right font-mono text-[11px] text-emerald-100/35">Latest incremental update · {new Date(graph.updates[0].created_at).toLocaleString()} · {graph.updates[0].source_event}</p>}
    </section>
  );
}

function Metric({ label, value, accent, compact = false }: { label: string; value: string | number; accent: string; compact?: boolean }) {
  return <div className="rounded-xl border border-emerald-400/15 bg-[#07191a] p-4"><p className="font-mono text-[10px] uppercase tracking-[0.18em] text-emerald-100/40">{label}</p><p className={`mt-2 font-mono ${compact ? "text-base" : "text-2xl"} ${accent}`}>{value}</p></div>;
}
