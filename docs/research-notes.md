# Phase 0 Research Notes

## SSRF and Egress Safety

OWASP’s SSRF guidance treats user-controlled URLs as difficult to validate safely, recommends controlling redirects, monitoring DNS resolution so public names cannot resolve into private addresses, and applying network-layer segmentation to block illegitimate routes. The design will therefore use a separate admission service, canonical URL parsing, pre-connect and post-connect IP checks, redirect-by-redirect revalidation, a strict protocol/port policy, and network policy that denies private, loopback, link-local, unique-local, carrier-grade NAT, multicast, and metadata destinations. [1]

## Worker and Queue Characteristics

Celery is documented as a distributed task queue focused on real-time processing and scheduling, with support for tasks, worker routing, monitoring, retries, and concurrency. Redis Streams provides append-only streams and consumer-group commands, including group reads and acknowledgement-oriented processing. These characteristics support either a Python-centric Celery implementation or a leaner Redis Streams worker architecture. The Phase 0 recommendation will use Celery with Redis as a broker/result-control plane for isolated crawl and browser workers, while retaining PostgreSQL as the authoritative job and evidence store; Kafka is deferred because the first release does not require multi-consumer event replay at Kafka’s operational cost. [2] [3]

## Automation Boundaries and Quality Standards

Playwright browser contexts are clean-slate, incognito-like isolated sessions with separate local storage, session storage, and cookies. The browser worker design will create one non-persistent context per scan and destroy it after the bounded scan, preventing cross-scan session carry-over. [4]

WCAG 2.2 is intended to be testable using both automated testing and human evaluation. Accordingly, automated accessibility output will identify deterministic signals and label limitations rather than asserting full compliance. [5]

## Sources

[1]: https://cheatsheetseries.owasp.org/cheatsheets/Server_Side_Request_Forgery_Prevention_Cheat_Sheet.html "OWASP Server-Side Request Forgery Prevention Cheat Sheet"
[2]: https://docs.celeryq.dev/en/stable/ "Celery 5.6 Documentation"
[3]: https://redis.io/docs/latest/develop/data-types/streams/ "Redis Streams Documentation"
[4]: https://playwright.dev/docs/browser-contexts "Playwright: Browser Context Isolation"
[5]: https://www.w3.org/TR/WCAG22/ "W3C Web Content Accessibility Guidelines 2.2"
