"""Veritabanındaki tehdit istihbaratı kayıtlarından anlık URL ve alan adı sorgulama."""

from __future__ import annotations

import logging

from sqlalchemy import func, or_, select
from sqlalchemy.ext.asyncio import AsyncSession

from api.db.models import ThreatIndicator
from api.schemas.analyze import SignalItem
from api.tools.domain import parse_host
from ingest.feeds import normalize_url

logger = logging.getLogger(__name__)


async def check_urls_in_db(urls: list[str], session: AsyncSession | None) -> list[SignalItem]:
    """Verilen URL'leri veya alan adlarını threat_indicators tablosunda sorgular."""
    if not urls or session is None:
        return []

    norm_urls = [normalize_url(u) for u in urls if u.strip()]
    hosts = [h for h in {parse_host(u) for u in norm_urls} if h]
    if not norm_urls and not hosts:
        return []

    try:
        stmt = select(ThreatIndicator).where(
            or_(
                ThreatIndicator.indicator.in_(norm_urls),
                ThreatIndicator.host.in_(hosts),
            )
        )
        result = await session.execute(stmt)
        matches = list(result.scalars().all())
    except Exception as exc:  # noqa: BLE001
        logger.warning("Tehdit istihbaratı veritabanı sorgusu atlandı: %s", exc)
        return []

    signals: list[SignalItem] = []
    exact_urls_found: set[str] = set()
    hosts_found: set[str] = set()

    for row in matches:
        if row.indicator in norm_urls and row.indicator not in exact_urls_found:
            exact_urls_found.add(row.indicator)
            signals.append(
                SignalItem(
                    source="url_intel",
                    name="known_malicious_url",
                    detail=(
                        f"Bu bağlantı '{row.source}' tehdit istihbaratı listesinde "
                        f"({row.threat_type}) kayıtlıdır."
                    ),
                    weight=0.92,
                )
            )
        elif row.host in hosts and row.host not in hosts_found:
            hosts_found.add(row.host)
            signals.append(
                SignalItem(
                    source="url_intel",
                    name="known_malicious_host",
                    detail=(
                        f"'{row.host}' alan adı '{row.source}' tehdit istihbaratı listesinde "
                        f"({row.threat_type}) daha önce zararlı olarak işaretlenmiştir."
                    ),
                    weight=0.82,
                )
            )

    return signals


async def get_threat_stats(session: AsyncSession) -> dict[str, int]:
    """Kaynak bazında kayıtlı tehdit istihbaratı sayılarını döndürür."""
    stmt = select(ThreatIndicator.source, func.count(ThreatIndicator.id)).group_by(
        ThreatIndicator.source
    )
    result = await session.execute(stmt)
    counts = {str(source): int(count) for source, count in result.all()}
    counts["total"] = sum(counts.values())
    return counts
