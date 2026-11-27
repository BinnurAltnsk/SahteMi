import httpx
import pytest
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker, create_async_engine

from api.db.models import Base
from api.tools.url_intel import check_urls_in_db, get_threat_stats
from ingest.feeds import fetch_urlhaus, parse_plain_url_feed, parse_usom_response
from ingest.sync import upsert_threats


def test_parse_plain_url_feed_filters_comments_and_deduplicates() -> None:
    sample = (
        "# URLhaus comment\n"
        "\n"
        "https://evil-phish.xyz/login/\n"
        "https://evil-phish.xyz/login\n"
        "http://malware-drop.top/app.apk\n"
    )
    items = parse_plain_url_feed(sample, source="openphish", threat_type="phishing")
    assert len(items) == 2
    assert items[0].indicator == "https://evil-phish.xyz/login"
    assert items[0].host == "evil-phish.xyz"
    assert items[1].host == "malware-drop.top"


@pytest.mark.asyncio
async def test_upsert_and_lookup_url_and_host() -> None:
    engine = create_async_engine("sqlite+aiosqlite:///:memory:")
    async with engine.begin() as conn:
        await conn.run_sync(Base.metadata.create_all)

    factory = async_sessionmaker(bind=engine, class_=AsyncSession, expire_on_commit=False)
    items = parse_plain_url_feed(
        "https://sahte-kargo.xyz/odeme\nhttp://zararli-site.top/payload.apk\n",
        source="openphish",
        threat_type="phishing",
    )

    async with factory() as session:
        ins1, upd1 = await upsert_threats(session, items)
        assert (ins1, upd1) == (2, 0)

        # İkinci kez aynı kayıtlar gelince yeni ekleme yerine güncelleme yapmalı
        ins2, upd2 = await upsert_threats(session, items)
        assert (ins2, upd2) == (0, 2)

        # Tam URL eşleşmesi
        exact = await check_urls_in_db(["https://sahte-kargo.xyz/odeme/"], session)
        assert len(exact) == 1
        assert exact[0].name == "known_malicious_url"
        assert exact[0].weight >= 0.9

        # Aynı alan adında farklı path -> host eşleşmesi
        host_match = await check_urls_in_db(["https://sahte-kargo.xyz/yeni-sayfa"], session)
        assert len(host_match) == 1
        assert host_match[0].name == "known_malicious_host"

        # Temiz adres -> eşleşme yok
        clean = await check_urls_in_db(["https://turkiye.gov.tr"], session)
        assert clean == []

        stats = await get_threat_stats(session)
        assert stats["openphish"] == 2
        assert stats["total"] == 2

    await engine.dispose()


def test_parse_usom_response_extracts_domains_and_phishing_type() -> None:
    payload = {
        "totalCount": 2,
        "page": 1,
        "pageCount": 1,
        "models": [
            {
                "id": 101,
                "url": "sahte-edevlet-giris.xyz",
                "type": "domain",
                "desc": "Bankacılık - Oltalama",
                "connectiontype": "Oltalama",
            },
            {
                "id": 102,
                "url": "https://zararli-apk.top/indir.apk/",
                "type": "url",
                "desc": "Zararlı Yazılım",
            },
            {
                "id": 103,
                "url": "sahte-edevlet-giris.xyz",
                "type": "domain",
                "desc": "Oltalama",
            },
        ],
    }
    items = parse_usom_response(payload)
    assert len(items) == 2
    assert items[0].source == "usom"
    assert items[0].indicator == "sahte-edevlet-giris.xyz"
    assert items[0].indicator_type == "domain"
    assert items[0].host == "sahte-edevlet-giris.xyz"
    assert items[0].threat_type == "phishing"
    assert items[1].threat_type == "malware"


@pytest.mark.asyncio
async def test_fetch_urlhaus_skips_when_auth_key_missing() -> None:
    def fail_if_called(_request: httpx.Request) -> httpx.Response:
        raise AssertionError("auth_key yokken HTTP isteği yapılmamalı")

    async with httpx.AsyncClient(transport=httpx.MockTransport(fail_if_called)) as client:
        items = await fetch_urlhaus(client, auth_key="")
        assert items == []
