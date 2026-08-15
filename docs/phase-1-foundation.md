# Phase 1 Foundation Notes

Phase 1 establishes two independent application boundaries. The Next.js frontend owns the engineering-tool user interface and a typed health client. The FastAPI backend owns configuration, HTTP routing, structured logs, health reporting, the SQLAlchemy engine, Alembic integration, and a deliberately non-functional authentication dependency contract.

No collection, scanning, technology inference, URL admission, evidence, browser, queue, or AI features are introduced. Those capabilities remain future-phase additions under the Phase 0 evidence and security model.

For local Compose configuration, copy `config/local.env.example` to `.env`. For direct service execution, use `frontend/config.env.example` and `backend/config.env.example` as the service-scoped equivalents. The managed workspace prevents automated creation of files named `.env*`; these non-dot templates preserve the same documented values without storing a real secret.

The Alembic revision `0001_phase1_baseline` is intentionally empty. It proves migration tooling and reserves future schema changes for additive, reviewed migrations rather than creating premature business tables.
