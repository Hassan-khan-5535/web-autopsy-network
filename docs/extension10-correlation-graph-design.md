# Extension 10 — Correlation & Attack-Surface Graph Agent

## Purpose and boundary

The Correlation Agent builds a **per-scan, evidence-backed attack-surface graph** from records already collected by the controlled crawler and existing analysis agents. It exists solely to prioritize investigation and make associations reviewable. It does not initiate network activity, attempt credentials, generate exploit payloads, submit forms, alter target state, or claim that a relationship proves exploitability.

Every node and edge must retain provenance, confidence, classification, and timestamps. An inferred association is explicitly labeled as inferred. A missing relationship is not interpreted as absence of risk.

## Graph storage contract

`attack_surface_graph_nodes` stores a stable graph node per `(scan_id, entity_type, natural_key)`. The allowed entity types are `Domain`, `Host`, `Service`, `Technology`, `Application`, `Endpoint`, `API`, `Parameter`, `Authentication Boundary`, `Finding`, `Evidence`, and `Cloud Asset`.

`attack_surface_graph_edges` stores a stable edge per `(scan_id, relationship_type, source_node_id, target_node_id)`. The relationship types are bounded to `OWNS`, `ASSOCIATED_WITH`, `EXPOSES`, `DEPENDS_ON`, `SHARES_CONFIGURATION_WITH`, `AFFECTS`, `DUPLICATES`, `RELATED_VULNERABILITY`, `HAS_EVIDENCE`, and `POTENTIAL_ESCALATION_PRIORITY`.

`attack_surface_graph_updates` records each correlation run. It captures the source event, the number of inserted or refreshed nodes and edges, and the correlation version. This makes subsequent agent discoveries incremental and reviewable.

## Correlation inputs

The agent derives nodes and edges only from existing, bounded evidence: scan URL and website origin, crawled pages and links, recon assets/endpoints/parameters, API endpoints, technology detections, dependencies, HTTP observations, security findings, evidence reviews, and technology-CVE matches.

Entity relationships are constructed deterministically. For example, a normalized endpoint belongs to the application and host inferred from its stored URL; a recon parameter belongs to its normalized endpoint; an API belongs to its observed endpoint; a technology dependency is associated with the application; and a finding affects only assets or endpoints where stored evidence identifies a direct connection.

## Incremental behavior

The Correlation Agent is scheduled after the existing evidence stage. Its idempotent upsert process refreshes existing natural keys and inserts newly discovered nodes and edges. It is safe to re-run after later evidence changes: previous correlation records are not deleted unless they are superseded by the same natural key, preserving an update trail.

## Prioritization-only paths

The report may expose a small, deterministic list of **potential escalation priority paths**. These are not attack chains. They identify a high- or critical-severity finding, an affected in-scope asset or endpoint, and the supporting evidence references so an engineer can review the relationship. Each path includes the statement `Prioritization only — not an exploit path or proof of exploitability.`

## API response

`GET /v1/scans/{scan_id}/attack-surface-graph` returns graph nodes, edges, update metadata, a summary by entity and relationship type, and prioritization-only paths. The response contains no raw secret values and excludes redacted evidence values.

## Frontend presentation

The report adds an **Attack Surface Graph** section. The section provides counts, filters by entity and relationship type, a bounded graph list, provenance per selected item, and priority-review paths. It does not expose any action that performs scanning or exploitation.
