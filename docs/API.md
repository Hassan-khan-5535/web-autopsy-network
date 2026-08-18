# Web Autopsy Network — API Reference Documentation

**Specification:** OpenAPI 3.0 / REST API Reference  
**Base URL:** `http://localhost:8000/v1`  

---

## Endpoints Summary

| Endpoint | Method | Description |
|---|---|---|
| `/health` | GET | Database & system health check |
| `/v1/scans` | POST | Enqueues a new URL autopsy scan immediately (`202 Accepted`) |
| `/v1/scans/{id}` | GET | Returns scan status, requested URL, and configuration |
| `/v1/scans/{id}/cancel` | POST | Requests cancellation of an in-flight scan |
| `/v1/scans/{id}/progress` | GET | Returns task progress, percentage, and queue status |
| `/v1/scans/{id}/progress/stream` | GET | Server-Sent Events (SSE) live progress stream |
| `/v1/scans/{id}/overview` | GET | Executive overview of scan findings |
| `/v1/scans/{id}/technologies` | GET | Technology DNA detections |
| `/v1/scans/{id}/architecture` | GET | Site URL hierarchy & domain tree |
| `/v1/scans/{id}/dependencies` | GET | External scripts, stylesheets, and third-party origins |
| `/v1/scans/{id}/security` | GET | Passive security header & cookie findings |
| `/v1/scans/{id}/performance` | GET | LCP, FID, CLS, and render-blocking metrics |
| `/v1/scans/{id}/accessibility` | GET | WCAG accessibility violation findings |
| `/v1/scans/{id}/content` | GET | Content structure & SEO findings |
| `/v1/scans/{id}/evidence` | GET | Searchable full evidence dataset |
| `/v1/scans/{id}/diagnosis` | GET | Cause of Death diagnostic verdict card |
| `/v1/scans/{id}/ask` | POST | Interactive AI Doctor Q&A (citation-grounded) |
| `/v1/workers/health` | GET | Worker pool active tasks and heartbeat freshness |

---

## Detailed Endpoint Specs

### 1. `POST /v1/scans`
Submits a new URL for forensic autopsy analysis. Returns immediately with `state: QUEUED`.

**Request Body:**
```json
{
  "url": "https://example.com",
  "max_depth": 2,
  "max_pages": 15
}
```

**Response (202 Accepted):**
```json
{
  "id": "39ada241-6713-476c-8d36-692afbe4544f",
  "requested_url": "https://example.com",
  "state": "QUEUED",
  "created_at": "2026-08-18T08:00:00Z"
}
```

### 2. `POST /v1/scans/{id}/ask`
Queries the AI Doctor regarding a specific scan's evidence context.

**Request Body:**
```json
{
  "question": "What are the primary security vulnerabilities?"
}
```

**Response (200 OK):**
```json
{
  "category": "SECURITY",
  "subject": "Missing Content-Security-Policy",
  "statement": "The origin lacks a Content-Security-Policy header, leaving it exposed to XSS.",
  "classification": "AI_INTERPRETATION",
  "evidence": ["sec_csp_missing"]
}
```
