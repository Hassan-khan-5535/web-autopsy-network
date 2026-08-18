import pytest
from sqlalchemy import event
from sqlalchemy.orm import Session
from app.services.evidence import get_scan_full_evidence_optimized
from app.models.scan import Scan, Website

def test_n_plus_one_query_budget(db: Session):
    website = Website(canonical_origin="https://example.com")
    db.add(website)
    db.commit()

    scan = Scan(website_id=website.id, requested_url="https://example.com", state="COMPLETED")
    db.add(scan)
    db.commit()


    
    query_count = 0
    def count_queries(conn, cursor, statement, parameters, context, executemany):
        nonlocal query_count
        query_count += 1

    event.listen(db.bind, "before_cursor_execute", count_queries)
    try:
        result = get_scan_full_evidence_optimized(db, scan.id)
        assert result is not None
        assert query_count <= 12

    finally:
        event.remove(db.bind, "before_cursor_execute", count_queries)


def test_cache_set_get():
    from app.services.cache import set_cache, get_cache, delete_cache
    key = "test_scan_report_123"
    data = {"status": "COMPLETED", "overview": "Everything clean"}

    set_cache(key, data, ttl_seconds=60)
    cached = get_cache(key)
    assert cached == data

    delete_cache(key)
    assert get_cache(key) is None


