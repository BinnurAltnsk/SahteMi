"""RDAP (Registration Data Access Protocol) üzerinden alan adı yaşı analizi.

Sıfır gün (zero-day) oltalama alan adlarının büyük bölümü saldırıdan birkaç gün
önce kaydedilir. Bu araç ücretsiz ve standart RDAP sorgusuyla kayıt tarihini
okuyup yeni alan adları için risk sinyali üretir.
"""

from __future__ import annotations

import asyncio
import logging
import time
from datetime import UTC, datetime

import httpx

from api.schemas.analyze import SignalItem
from api.tools.domain import IPV4_HOST_RE, find_official_brand, parse_host

logger = logging.getLogger(__name__)

RDAP_BASE_URL = "https://rdap.org/domain"
RDAP_CACHE_TTL_SECONDS = 6 * 3600
RDAP_CACHE_MAX_ENTRIES = 1024
MAX_DOMAINS_PER_REQUEST = 3

# İki parçalı yaygın ülke uzantıları (registrable domain çıkarımı için)
MULTI_PART_TLDS: set[str] = {
    "com.tr",
    "gov.tr",
    "org.tr",
    "net.tr",
    "edu.tr",
    "bel.tr",
    "pol.tr",
    "mil.tr",
    "k12.tr",
    "av.tr",
    "dr.tr",
    "gen.tr",
    "biz.tr",
    "info.tr",
    "web.tr",
    "co.uk",
    "org.uk",
    "gov.uk",
    "com.br",
    "com.au",
}

# domain -> (cached_monotonic_ts, registration_datetime | None)
_RDAP_CACHE: dict[str, tuple[float, datetime | None]] = {}


def clear_rdap_cache() -> None:
    """Testler veya bakım için bellek içi RDAP önbelleğini temizler."""
    _RDAP_CACHE.clear()


def extract_registrable_domain(host: str) -> str:
    """Alt alan adından RDAP sorgulanabilir kök alan adını çıkarır."""
    cleaned = host.lower().strip(".")
    if not cleaned or IPV4_HOST_RE.match(cleaned):
        return ""

    parts = cleaned.split(".")
    if len(parts) < 2:
        return ""

    last_two = ".".join(parts[-2:])
    if last_two in MULTI_PART_TLDS and len(parts) >= 3:
        return ".".join(parts[-3:])
    return last_two


def parse_rdap_registration_date(payload: dict) -> datetime | None:
    """RDAP JSON yanıtındaki `registration` olay tarihini UTC datetime olarak döndürür."""
    events = payload.get("events")
    if not isinstance(events, list):
        return None

    for event in events:
        if not isinstance(event, dict):
            continue
        action = str(event.get("eventAction", "")).lower().strip()
        if action not in {"registration", "registered"}:
            continue
        raw_date = event.get("eventDate")
        if not isinstance(raw_date, str) or not raw_date.strip():
            continue
        iso_str = raw_date.strip().replace("Z", "+00:00")
        try:
            dt = datetime.fromisoformat(iso_str)
            if dt.tzinfo is None:
                dt = dt.replace(tzinfo=UTC)
            return dt.astimezone(UTC)
        except ValueError:
            continue

    return None


def evaluate_domain_age(
    domain: str,
    created_at: datetime,
    *,
    now: datetime | None = None,
) -> SignalItem | None:
    """Alan adının yaşına göre risk sinyali üretir."""
    ref_now = now or datetime.now(UTC)
    age_days = max(0, (ref_now - created_at.astimezone(UTC)).days)

    if age_days <= 14:
        return SignalItem(
            source="domain",
            name="very_new_domain",
            detail=(
                f"'{domain}' alan adı yalnızca {age_days} gün önce kaydedilmiş "
                "(çok yeni alan adı, oltalama riski yüksek)."
            ),
            weight=0.55,
        )

    if age_days <= 45:
        return SignalItem(
            source="domain",
            name="new_domain",
            detail=(
                f"'{domain}' alan adı {age_days} gün önce kaydedilmiş (yeni kayıtlı alan adı)."
            ),
            weight=0.35,
        )

    return None


async def fetch_domain_registration_date(
    domain: str,
    client: httpx.AsyncClient,
    *,
    timeout: float = 2.5,
) -> datetime | None:
    """RDAP üzerinden tek bir alan adının kayıt tarihini getirir (TTL önbellekli)."""
    now_mono = time.monotonic()
    cached = _RDAP_CACHE.get(domain)
    if cached is not None and (now_mono - cached[0]) < RDAP_CACHE_TTL_SECONDS:
        return cached[1]

    created_at: datetime | None = None
    try:
        response = await client.get(
            f"{RDAP_BASE_URL}/{domain}",
            timeout=timeout,
            follow_redirects=True,
        )
        if response.status_code == 200:
            data = response.json()
            if isinstance(data, dict):
                created_at = parse_rdap_registration_date(data)
    except Exception as exc:  # noqa: BLE001
        logger.debug("RDAP sorgusu atlandı (%s): %s", domain, exc)
        return None

    if len(_RDAP_CACHE) >= RDAP_CACHE_MAX_ENTRIES:
        _RDAP_CACHE.clear()
    _RDAP_CACHE[domain] = (now_mono, created_at)
    return created_at


async def check_domains_rdap(
    urls: list[str],
    *,
    client: httpx.AsyncClient | None = None,
    timeout: float = 2.5,
    now: datetime | None = None,
) -> list[SignalItem]:
    """URL listesindeki doğrulanmamış alan adları için RDAP yaş kontrolü yapar."""
    if not urls:
        return []

    domains: list[str] = []
    for url in urls:
        host = parse_host(url)
        if not host or find_official_brand(host) is not None:
            continue
        reg_domain = extract_registrable_domain(host)
        if reg_domain and reg_domain not in domains:
            domains.append(reg_domain)
        if len(domains) >= MAX_DOMAINS_PER_REQUEST:
            break

    if not domains:
        return []

    async def _run(http_client: httpx.AsyncClient) -> list[SignalItem]:
        dates = await asyncio.gather(
            *(fetch_domain_registration_date(dom, http_client, timeout=timeout) for dom in domains)
        )
        signals: list[SignalItem] = []
        for dom, created_at in zip(domains, dates, strict=True):
            if created_at is None:
                continue
            signal = evaluate_domain_age(dom, created_at, now=now)
            if signal is not None:
                signals.append(signal)
        return signals

    if client is not None:
        return await _run(client)

    headers = {"Accept": "application/rdap+json, application/json", "User-Agent": "SahteMi/0.1"}
    async with httpx.AsyncClient(headers=headers) as own_client:
        return await _run(own_client)
