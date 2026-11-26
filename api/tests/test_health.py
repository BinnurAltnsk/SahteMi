from fastapi.testclient import TestClient

from api.main import app

client = TestClient(app)


def test_health_returns_ok() -> None:
    response = client.get("/health")
    assert response.status_code == 200
    data = response.json()
    assert data["status"] == "ok"
    assert data["service"] == "SahteMi"


def test_analyze_detects_scam_and_extracts_urls() -> None:
    payload = {
        "text": "Kargonuz teslim edilemedi, adresinizi guncelleyin: https://ptt-kargo-ornek.xyz/takip",
        "channel": "sms",
    }
    response = client.post("/api/v1/analyze", json=payload)
    assert response.status_code == 200
    data = response.json()
    assert data["risk_level"] == "scam"
    assert data["risk_score"] >= 0.65
    assert data["extracted_urls"] == ["https://ptt-kargo-ornek.xyz/takip"]
    assert len(data["signals"]) >= 1


def test_analyze_rejects_too_short_text() -> None:
    response = client.post("/api/v1/analyze", json={"text": "a"})
    assert response.status_code == 422
