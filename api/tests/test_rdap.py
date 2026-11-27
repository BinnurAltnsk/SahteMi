from datetime import UTC, datetime, timedelta

import httpx
import pytest

from api.tools.rdap import (
    check_domains_rdap,
    clear_rdap_cache,
    evaluate_domain_age,
    extract_registrable_domain,
    parse_rdap_registration_date,
)


def test_extract_registrable_domain() -> None:
    assert extract_registrable_domain("odeme.ptt-takip.xyz") == "ptt-takip.xyz"
    assert extract_registrable_domain("alt.ornek.com.tr") == "ornek.com.tr"
    assert extract_registrable_domain("turkiye.gov.tr") == "turkiye.gov.tr"
    assert extract_registrable_domain("192.168.1.10") == ""


def test_parse_rdap_registration_date_and_evaluate_age() -> None:
    now = datetime(2026, 11, 27, 12, 0, tzinfo=UTC)
    payload = {
        "events": [
            {"eventAction": "last changed", "eventDate": "2026-11-26T00:00:00Z"},
            {"eventAction": "registration", "eventDate": "2026-11-22T10:00:00Z"},
        ]
    }
    created = parse_rdap_registration_date(payload)
    assert created == datetime(2026, 11, 22, 10, 0, tzinfo=UTC)

    very_new = evaluate_domain_age("sahte-kargo.xyz", created, now=now)
    assert very_new is not None
    assert very_new.name == "very_new_domain"
    assert very_new.weight == 0.55

    medium_new = evaluate_domain_age("yeni-site.xyz", now - timedelta(days=30), now=now)
    assert medium_new is not None
    assert medium_new.name == "new_domain"
    assert medium_new.weight == 0.35

    old_domain = evaluate_domain_age("eski-site.com", now - timedelta(days=400), now=now)
    assert old_domain is None


@pytest.mark.asyncio
async def test_check_domains_rdap_skips_official_and_caches() -> None:
    clear_rdap_cache()
    now = datetime(2026, 11, 27, 12, 0, tzinfo=UTC)
    recent_iso = (now - timedelta(days=3)).isoformat().replace("+00:00", "Z")
    calls: list[str] = []

    def handler(request: httpx.Request) -> httpx.Response:
        calls.append(request.url.path)
        if request.url.path.endswith("/yeni-oltalama.xyz"):
            return httpx.Response(
                200,
                json={"events": [{"eventAction": "registration", "eventDate": recent_iso}]},
            )
        return httpx.Response(404)

    async with httpx.AsyncClient(transport=httpx.MockTransport(handler)) as client:
        # Resmi kurum adresi sorgulanmamalı, yeni alan adı işaretlenmeli
        signals = await check_domains_rdap(
            ["https://turkiye.gov.tr", "https://sub.yeni-oltalama.xyz/giris"],
            client=client,
            now=now,
        )
        assert len(signals) == 1
        assert signals[0].name == "very_new_domain"
        assert calls == ["/domain/yeni-oltalama.xyz"]

        # İkinci çağrı önbellekten dönmeli (ek HTTP isteği yapmamalı)
        signals_cached = await check_domains_rdap(
            ["https://yeni-oltalama.xyz/odeme"],
            client=client,
            now=now,
        )
        assert len(signals_cached) == 1
        assert calls == ["/domain/yeni-oltalama.xyz"]

    clear_rdap_cache()
