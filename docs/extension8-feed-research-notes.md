# Extension 8 Feed Research Notes

Date: 2026-08-19

## NVD

Official NVD documentation: https://nvd.nist.gov/developers/vulnerabilities

The NVD CVE API base URL is `https://services.nvd.nist.gov/rest/json/cves/2.0`. The official documentation states that the API returns CVE records and uses offset-based pagination with `startIndex` and `resultsPerPage` for large collections. NVD also provides a CVE change-history API at `https://services.nvd.nist.gov/rest/json/cvehistory/2.0`. NVD is the primary feed for CVE descriptions, configurations/CPE applicability data, CWE references, CVSS metadata, and publication/last-modified timestamps.

Extension 8 should use NVD CPE applicability ranges only when the detected product has a normalized vendor/product/version with sufficient version evidence. A technology-family match without a version must remain non-applicable/unknown rather than producing a CVE finding.

## CISA KEV

Official CISA catalog: https://www.cisa.gov/known-exploited-vulnerabilities-catalog

CISA describes the Known Exploited Vulnerabilities Catalog as a maintained source for vulnerabilities exploited in the wild and recommends it as an input to vulnerability-management prioritization. The catalog provides CVE ID, description, CWE, vendor/project, date added, due date, exploitation/ransomware status, notes, and mitigation fields. It is available as JSON, CSV, and JSON Schema. The official JSON feed is linked from the catalog and is suitable for a timestamped provenance record.

Extension 8 should use KEV membership as an exploitation-priority signal, not as proof that a detected technology is affected. KEV enrichment must remain separate from affected-version matching and CVE-applicability confidence.

## Design implications

The normalized vulnerability record should preserve source name, source URL, feed retrieval timestamp, source publication/last-modified timestamps when available, stale threshold, CVE ID, CWE, CVSS vector and score, description, affected version constraints, KEV membership, and dedupe identity. A report should separately expose detected technology confidence and CVE applicability confidence, along with an explicit state such as `matched`, `version_insufficient`, `not_applicable`, or `stale_feed`.

## OSV

Official OSV documentation: https://google.github.io/osv.dev/

OSV describes itself as an aggregator of vulnerability databases using the OpenSSF Vulnerability format. Its infrastructure represents affected versions accurately and supports querying by package/version or commit hash. OSV is especially suitable for normalized open-source package/dependency intelligence, while NVD remains the primary source for CPE-oriented web technology matching in this extension. OSV enrichment should preserve ecosystem/package provenance and must not be treated as a substitute for sufficient vendor/product/version evidence.
