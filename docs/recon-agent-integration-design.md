# Extension 2 Recon Agent integration design

The Recon Agent will reuse the existing `CrawlerService`, `AdmissionService`, `TechnologyDetectionService`, `StructureAgent`, `ApiIntelligenceAgent`, `NetworkIntelligenceAgent`, `Page`, `Resource`, `PageLink`, `Observation`, `Technology`, `Dependency`, `ApiEndpoint`, and `AgentTask` infrastructure. No second crawler, technology engine, dependency graph, or API-discovery subsystem will be introduced.

The current crawler already enforces assessment scope, robots rules, redirects, request budgets, rate limits, and SSRF admission. It persists page, response, header, resource, link, and observation evidence. The structure agent already extracts forms and classifies page types. The API intelligence agent already extracts API candidates from form actions, resource URLs, fetch, Axios, jQuery, and XHR patterns. The technology engine is driven by the versioned JSON signature catalog. The network-intelligence agent already groups external domains from resources and external links.

Recon-specific additions should normalize these existing outputs into additive `ReconAsset`, `ReconEndpoint`, and `ReconParameter` records with a source, mode (`passive` or `active_safe`), classification, confidence, scope decision, evidence reference, and idempotency key. Existing tables remain authoritative for existing report sections; normalized records are an additive cross-source index.

Passive public-source adapters should use bounded HTTPS requests to the public Certificate Transparency API and Google Public DNS JSON API. The CT adapter should parse certificate `dns_names`/`name_value` hostnames, remove wildcard prefixes, keep only hostnames within the authorized domain scope, and record source URLs and timestamps. The DNS adapter should query A, AAAA, CNAME, MX, NS, and TXT records through the documented `https://dns.google/resolve?name=...&type=...` JSON interface and treat `Status`, `Answer`, and DNS data as observations rather than vulnerability conclusions.

The CT and DNS adapters must be passive-only: they do not connect to discovered hosts. Active-safe mode may perform only bounded, scope-checked GET/HEAD discovery of sitemap-declared URLs, robots-declared sitemap URLs, a small maintainable path-wordlist, and URLs already extracted from JavaScript/API patterns. It must reuse the crawler’s admission, scope, robots, request-budget, and rate-limit controls, and must not submit forms, mutate state, brute-force credentials, or probe arbitrary ports.

Cloud/public-asset detection should classify observed URLs and hostnames matching S3 virtual-host/path styles, Azure Blob endpoints, GCS storage endpoints, and common public bucket URL patterns. This is passive classification based on stored URLs; it is not permission or exposure proof and should state that limitation in evidence.

The public DNS JSON API documents GET parameters such as `name` and `type`, with JSON `Status`, `Question`, and `Answer` fields. The public Certificate Transparency search API documents JSON issuance records with DNS names. Both adapters should set short timeouts, bounded result counts, a clear user agent, and failure observations rather than failing the whole scan.

## References

[1] [Google Public DNS JSON API specification](https://developers.google.com/speed/public-dns/docs/doh/json), including supported `name` and `type` parameters and JSON `Status`, `Question`, and `Answer` fields.

[2] [SSLMate Certificate Transparency Search API](https://sslmate.com/ct_search_api/), documenting JSON issuance records with certificate DNS names.

[3] [crt.sh Certificate Search](https://crt.sh/), used as a bounded fallback public CT source when the primary issuance API is unavailable.
