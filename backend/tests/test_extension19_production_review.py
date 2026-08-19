from uuid import uuid4

from sqlalchemy import create_engine
from sqlalchemy.orm import Session

from app.models.scan import Base, Scan, Website
from app.core.config import DEFAULT_JWT_SECRET, DEFAULT_UPDATE_PACKAGE_HMAC_KEY, Settings
from app.services.correlation import CorrelationAgent


def test_graph_upserts_recover_from_stale_writer_duplicate_key_race(tmp_path):
    engine = create_engine(f"sqlite+pysqlite:///{tmp_path / 'graph-race.db'}")
    Base.metadata.create_all(engine)
    with Session(engine) as first, Session(engine) as second:
        website = Website(id=uuid4(), tenant_id="review", canonical_origin="example.com")
        first.add(website)
        first.flush()
        scan = Scan(id=uuid4(), website_id=website.id, requested_url="https://example.com", state="ANALYZING")
        first.add(scan)
        first.commit()

        first_agent = CorrelationAgent(first, scan.id)
        first_node = first_agent._node("Technology", "nginx", "nginx")
        first.commit()

        # The second agent starts with an intentionally stale empty in-memory node index.
        second_agent = CorrelationAgent(second, scan.id)
        recovered_node = second_agent._node("Technology", "nginx", "nginx")
        second.commit()

        assert recovered_node.id == first_node.id
        assert second.query(type(recovered_node)).filter_by(scan_id=scan.id, entity_type="Technology").count() == 1

        first_edge = first_agent._edge(first_node, first_node, "ASSOCIATED_WITH")
        first.commit()
        recovered_edge = second_agent._edge(recovered_node, recovered_node, "ASSOCIATED_WITH")
        second.commit()
        assert recovered_edge.id == first_edge.id
        assert second.query(type(recovered_edge)).filter_by(scan_id=scan.id, relationship_type="ASSOCIATED_WITH").count() == 1


def test_production_configuration_rejects_default_signing_keys_and_wildcard_cors():
    settings = Settings(
        app_env="production",
        jwt_secret=DEFAULT_JWT_SECRET,
        update_package_hmac_key=DEFAULT_UPDATE_PACKAGE_HMAC_KEY,
        cors_origins="*",
    )
    try:
        settings.validate_production_security()
    except ValueError as exc:
        assert "JWT_SECRET" in str(exc)
        assert "UPDATE_PACKAGE_HMAC_KEY" in str(exc)
        assert "CORS_ORIGINS" in str(exc)
    else:
        raise AssertionError("Production defaults must fail closed.")


def test_production_configuration_accepts_explicit_strong_keys_and_origins():
    settings = Settings(
        app_env="production",
        jwt_secret="j" * 32,
        update_package_hmac_key="u" * 32,
        cors_origins="https://console.example.com",
    )
    settings.validate_production_security()
