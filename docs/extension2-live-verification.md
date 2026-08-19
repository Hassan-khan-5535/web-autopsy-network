# Extension 2 live verification

The rebuilt scan form at the public port 3001 URL rendered the existing target, assessment profile, scope, rate limit, robots, and authentication controls plus a new `Recon Agent mode` selector with `Passive-only` and `Active-safe` options. The form copy states that passive mode uses stored evidence plus public Certificate Transparency and DNS observations, while active-safe mode performs bounded scope-checked GET discovery without form submission or mutation.

A real authorized Example.com active-safe scan completed successfully as scan `7a44d3b0-b461-401b-8906-666a596362b8`. The report UI showed the authorization record, Safe profile, consent hash prefix, target/domain/path scope, robots status, and the Recon Agent section. The Recon section displayed `active_safe`, `8/8 requests`, 15 assets, 14 endpoints, 0 parameters, 2 CT-derived subdomains, 0 cloud candidates, and 2 classified paths.

The normalized report contained CT/DNS observations, the in-scope page, an external IANA link retained as out-of-scope, and 13 active-safe candidate endpoints. Candidate classifications included `NOT_FOUND`, `ADMIN_PATH`, and `LOGIN_PATH`. The report displayed the limitation that cloud candidates are pattern observations rather than proof of public read access, and that CT/DNS results are passive observations.

The real Python.org passive-only verification completed successfully as scan `2ecf495b-229c-4c7b-9437-92c6eddf112c`. It used `6/10` scan requests and reported 336 assets, 11 endpoints, 29 parameters, 2 CT-derived subdomains, 0 cloud candidates, and 3 classified paths. Its Recon task succeeded on the first attempt.

The final restarted-service verification used scan `3e4f902c-0956-45f7-a415-3876a29112fb`. The live report showed `COMPLETED`, `active_safe`, `8/8 requests`, 15 assets, 14 endpoints, 0 parameters, 2 subdomains, and 2 classified paths. The Recon task succeeded on the first attempt. DNS values were correctly rendered with hostname `example.com` and `scope_status: in_scope`; the external IANA link remained `out_of_scope`. The Technology DNA section displayed the updated maintainable `phase4-v2` ruleset.
