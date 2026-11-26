"""OpenPhish ve URLhaus ücretsiz tehdit istihbaratı besleme okuyucuları."""

from __future__ import annotations

from dataclasses import dataclass

import httpx

from api.tools.domain import parse_host

OPENPHISH_FEED_URL = "https://openphish.com/feed.txt"
URLHAUS_FEED_URL = "https://urlhaus.abuse.ch/downloads/text_online/"


@dataclass(frozen=True)
class RawThreatItem:
    indicator: str
    host: str
    source: str
    threat_type: str
    indicator_type: str = "url"


def normalize_url(url: str) -> str:
    """URL'yi tutarlı sorgulama için normalize eder (boşluk ve sondaki '/' temizliği)."""
    return url.strip().rstrip("/")


def parse_plain_url_feed(
    text: str,
    *,
    source: str,
    threat_type: str,
    limit: int | None = None,
) -> list[RawThreatItem]:
    """Satır başına bir URL içeren düz metin beslemelerini ayrıştırır."""
    items: list[RawThreatItem] = []
    seen: set[str] = set()

    for line in text.splitlines():
        cleaned = line.strip()
        if not cleaned or cleaned.startswith("#"):
            continue
        norm = normalize_url(cleaned)
        if not norm or norm in seen:
            continue
        host = parse_host(norm)
        if not host:
            continue
        seen.add(norm)
        items.append(
            RawThreatItem(
                indicator=norm,
                host=host,
                source=source,
                threat_type=threat_type,
            )
        )
        if limit is not None and len(items) >= limit:
            break

    return items


async def fetch_openphish(
    client: httpx.AsyncClient,
    *,
    limit: int | None = None,
) -> list[RawThreatItem]:
    response = await client.get(OPENPHISH_FEED_URL, timeout=30.0)
    response.raise_for_status()
    return parse_plain_url_feed(
        response.text,
        source="openphish",
        threat_type="phishing",
        limit=limit,
    )


async def fetch_urlhaus(
    client: httpx.AsyncClient,
    *,
    limit: int | None = None,
) -> list[RawThreatItem]:
    response = await client.get(URLHAUS_FEED_URL, timeout=30.0)
    response.raise_for_status()
    return parse_plain_url_feed(
        response.text,
        source="urlhaus",
        threat_type="malware",
        limit=limit,
    )
