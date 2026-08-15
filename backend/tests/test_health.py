from fastapi.testclient import TestClient

from app.main import app

client = TestClient(app)


def test_health_reports_connected_database(monkeypatch) -> None:
    monkeypatch.setattr("app.api.routes.health.check_database_connection", lambda: True)

    response = client.get("/health")

    assert response.status_code == 200
    assert response.json()["status"] == "ok"
    assert response.json()["database"] == "connected"


def test_health_reports_degraded_database(monkeypatch) -> None:
    monkeypatch.setattr("app.api.routes.health.check_database_connection", lambda: False)

    response = client.get("/health")

    assert response.status_code == 503
    assert response.json()["status"] == "degraded"
    assert response.json()["database"] == "unavailable"
