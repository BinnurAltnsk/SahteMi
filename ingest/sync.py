"""Tehdit istihbaratı beslemelerini çekip PostgreSQL'e kaydeden CLI aracı.

Kullanım:
    python -m ingest.sync
    python -m ingest.sync --source usom --limit 200
    python -m ingest.sync --source openphish --limit 200
"""

from __future__ import annotations

import argparse
import asyncio
import logging
from datetime import UTC, datetime

import httpx
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from api.core.config import get_settings
from api.core.logging import setup_logging
from api.db.models import ThreatIndicator
from api.db.session import close_db, get_session_factory, init_db
from ingest.feeds import RawThreatItem, fetch_openphish, fetch_urlhaus, fetch_usom

logger = logging.getLogger(__name__)


async def upsert_threats(session: AsyncSession, items: list[RawThreatItem]) -> tuple[int, int]:
    """Kayıtları veritabanına ekler veya mevcutların last_seen_at zamanını günceller.

    Returns:
        (eklenen_sayisi, guncellenen_sayisi)
    """
    if not items:
        return 0, 0

    now = datetime.now(UTC)
    inserted = 0
    updated = 0

    # Büyük listelerde SQLite/Postgres parametre limitine takılmamak için parça parça işle
    chunk_size = 500
    for start in range(0, len(items), chunk_size):
        chunk = items[start : start + chunk_size]
        indicators = [item.indicator for item in chunk]

        stmt = select(ThreatIndicator).where(ThreatIndicator.indicator.in_(indicators))
        result = await session.execute(stmt)
        existing_map = {row.indicator: row for row in result.scalars().all()}

        for item in chunk:
            existing = existing_map.get(item.indicator)
            if existing is not None:
                existing.last_seen_at = now
                updated += 1
            else:
                session.add(
                    ThreatIndicator(
                        indicator=item.indicator,
                        indicator_type=item.indicator_type,
                        host=item.host,
                        source=item.source,
                        threat_type=item.threat_type,
                        first_seen_at=now,
                        last_seen_at=now,
                    )
                )
                inserted += 1

        await session.commit()

    return inserted, updated


async def run_sync(source: str = "all", limit: int | None = None) -> dict[str, tuple[int, int]]:
    settings = get_settings()
    setup_logging("INFO")
    db_ok = await init_db()
    if not db_ok:
        raise RuntimeError("Veritabanına bağlanılamadı. DATABASE_URL ayarını kontrol edin.")

    summary: dict[str, tuple[int, int]] = {}
    headers = {"User-Agent": "SahteMi-ThreatIngest/0.1"}

    try:
        async with httpx.AsyncClient(headers=headers, follow_redirects=True) as client:
            tasks: list[tuple[str, list[RawThreatItem]]] = []

            if source in {"all", "openphish"}:
                try:
                    op_items = await fetch_openphish(client, limit=limit)
                    tasks.append(("openphish", op_items))
                    logger.info("OpenPhish beslemesinden %d kayıt alındı.", len(op_items))
                except Exception as exc:  # noqa: BLE001
                    logger.error("OpenPhish beslemesi alınamadı: %s", exc)

            if source in {"all", "usom"}:
                try:
                    usom_items = await fetch_usom(client, limit=limit)
                    tasks.append(("usom", usom_items))
                    logger.info("USOM/SGB beslemesinden %d kayıt alındı.", len(usom_items))
                except Exception as exc:  # noqa: BLE001
                    logger.error("USOM/SGB beslemesi alınamadı: %s", exc)

            if source in {"all", "urlhaus"}:
                if not settings.urlhaus_auth_key.strip():
                    logger.info(
                        "URLhaus atlandı: URLHAUS_AUTH_KEY tanımlı değil "
                        "(ücretsiz anahtar: https://auth.abuse.ch/)."
                    )
                else:
                    try:
                        uh_items = await fetch_urlhaus(
                            client,
                            auth_key=settings.urlhaus_auth_key,
                            limit=limit,
                        )
                        tasks.append(("urlhaus", uh_items))
                        logger.info("URLhaus beslemesinden %d kayıt alındı.", len(uh_items))
                    except Exception as exc:  # noqa: BLE001
                        logger.error("URLhaus beslemesi alınamadı: %s", exc)

        factory = get_session_factory()
        async with factory() as session:
            for feed_name, items in tasks:
                ins, upd = await upsert_threats(session, items)
                summary[feed_name] = (ins, upd)
                logger.info("%s: %d yeni eklendi, %d güncellendi.", feed_name, ins, upd)
    finally:
        await close_db()

    return summary


def main() -> None:
    parser = argparse.ArgumentParser(description="Tehdit istihbaratı beslemelerini senkronize et.")
    parser.add_argument(
        "--source",
        choices=["all", "openphish", "usom", "urlhaus"],
        default="all",
        help="Çekilecek besleme kaynağı",
    )
    parser.add_argument(
        "--limit",
        type=int,
        default=None,
        help="Besleme başına en fazla kaç kayıt çekileceği (opsiyonel)",
    )
    args = parser.parse_args()
    asyncio.run(run_sync(source=args.source, limit=args.limit))


if __name__ == "__main__":
    main()
