import pytest
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker, create_async_engine

from api.db.models import Base
from api.tools.url_intel import check_urls_in_db, get_threat_stats
from ingest.feeds import parse_plain_url_feed
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
