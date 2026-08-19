# Real Authorized URL Testing Standard

All verification must use a real website URL that the user is authorized to assess. The application accepts a target only through the normal scan-submission flow, which records authorization and enforces the configured scope, bounded crawling, and policy limits.

Demo identifiers, static report substitutions, synthetic scan routes, and pre-analyzed demo payloads are not used for production verification. Browser checks should validate the public application URL, submitted real scan flow, persisted scan UUID report route, and the resulting API data.

Tests may use isolated database fixtures and mocked transport only to validate deterministic code behavior. They must not be presented as a live website assessment.
