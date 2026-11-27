"""OpenPhish, USOM (T.C. Siber Güvenlik Başkanlığı) ve URLhaus besleme okuyucuları."""

from __future__ import annotations

from dataclasses import dataclass

import httpx

from api.tools.domain import parse_host

OPENPHISH_FEED_URL = "https://openphish.com/feed.txt"
USOM_API_URL = "https://siberguvenlik.gov.tr/api/address/index"
URLHAUS_EXPORT_URL_TEMPLATE = (
    "https://urlhaus-api.abuse.ch/v2/files/exports/{auth_key}/text_online/"
)
DEFAULT_USOM_MAX_ITEMS = 1000


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


def _classify_usom_threat_type(entry: dict) -> str:
    raw_desc = str(entry.get("desc") or entry.get("description") or "").strip().lower()
    raw_conn = str(entry.get("connectiontype") or entry.get("connectionType") or "").strip().lower()
    combined = f"{raw_desc} {raw_conn}"

    if "phish" in combined or "oltalama" in combined or raw_desc == "bp":
        return "phishing"
    if "malware" in combined or "zararli" in combined or "zararlı" in combined:
        return "malware"
    if raw_desc:
        return raw_desc[:64]
    return "malicious"


def parse_usom_response(
    payload: dict,
    *,
    limit: int | None = None,
) -> list[RawThreatItem]:
    """USOM/SGB `/api/address/index` JSON yanıtındaki kayıtları ayrıştırır."""
    models = payload.get("models")
    if not isinstance(models, list):
        return []

    items: list[RawThreatItem] = []
    seen: set[str] = set()

    for entry in models:
        if not isinstance(entry, dict):
            continue
        raw_url = str(entry.get("url") or entry.get("address") or "").strip()
        if not raw_url:
            continue

        norm = normalize_url(raw_url)
        if not norm or norm in seen:
            continue

        host = parse_host(norm)
        if not host:
            continue

        raw_type = str(entry.get("type") or "").strip().lower()
        indicator_type = raw_type if raw_type in {"domain", "url", "ip"} else "url"
        seen.add(norm)
        items.append(
            RawThreatItem(
                indicator=norm,
                host=host,
                source="usom",
                threat_type=_classify_usom_threat_type(entry),
                indicator_type=indicator_type,
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


async def fetch_usom(
    client: httpx.AsyncClient,
    *,
    limit: int | None = None,
    per_page: int = 200,
) -> list[RawThreatItem]:
    """T.C. Siber Güvenlik Başkanlığı (USOM) API'sinden güncel zararlı adresleri çeker."""
    target = limit if limit is not None else DEFAULT_USOM_MAX_ITEMS
    page_size = min(max(1, per_page), target)
    collected: list[RawThreatItem] = []
    seen: set[str] = set()
    page = 1

    while len(collected) < target:
        response = await client.get(
            USOM_API_URL,
            params={"page": page, "per-page": page_size},
            timeout=30.0,
        )
        response.raise_for_status()
        payload = response.json()
        if not isinstance(payload, dict):
            break

        batch = parse_usom_response(payload)
        if not batch:
            break

        for item in batch:
            if item.indicator in seen:
                continue
            seen.add(item.indicator)
            collected.append(item)
            if len(collected) >= target:
                break

        page_count = int(payload.get("pageCount") or 1)
        if page >= page_count:
            break
        page += 1

    return collected


async def fetch_urlhaus(
    client: httpx.AsyncClient,
    *,
    auth_key: str = "",
    limit: int | None = None,
) -> list[RawThreatItem]:
    """URLhaus beslemesini çeker (abuse.ch anahtarlı uç noktası için auth_key gerektirir)."""
    key = auth_key.strip()
    if not key:
        return []

    url = URLHAUS_EXPORT_URL_TEMPLATE.format(auth_key=key)
    response = await client.get(url, timeout=30.0)
    response.raise_for_status()
    return parse_plain_url_feed(
        response.text,
        source="urlhaus",
        threat_type="malware",
        limit=limit,
    )
