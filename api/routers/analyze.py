import asyncio

from fastapi import APIRouter

from api.core.config import get_settings
from api.db.session import get_session_factory
from api.schemas.analyze import AnalyzeRequest, AnalyzeResponse, SignalItem
from api.tools.rdap import check_domains_rdap
from api.tools.rules import (
    _build_summary,
    _combine_weights,
    _score_to_level,
    analyze_with_rules,
)
from api.tools.url_intel import check_urls_in_db

router = APIRouter(prefix="/api/v1", tags=["analyze"])


async def _lookup_db_signals(urls: list[str]) -> list[SignalItem]:
    try:
        factory = get_session_factory()
        async with factory() as session:
            return await check_urls_in_db(urls, session)
    except Exception:  # noqa: BLE001
        return []


async def _lookup_rdap_signals(urls: list[str]) -> list[SignalItem]:
    settings = get_settings()
    if not settings.enable_rdap_lookup:
        return []
    try:
        return await check_domains_rdap(urls, timeout=settings.rdap_timeout_seconds)
    except Exception:  # noqa: BLE001
        return []


@router.post("/analyze", response_model=AnalyzeResponse)
async def analyze_message(payload: AnalyzeRequest) -> AnalyzeResponse:
    """Mesaj ve URL analizi uç noktası.

    Alan adı / marka taklidi analizi, Türkçe sosyal mühendislik kuralları,
    PostgreSQL tehdit istihbaratı (OpenPhish, USOM/SGB, URLhaus) ve RDAP
    alan adı yaşı kontrollerini birleştirerek gerekçeli risk sonucu döndürür.
    """
    result = analyze_with_rules(payload.text, channel=payload.channel)
    if not result.extracted_urls:
        return result

    intel_signals, rdap_signals = await asyncio.gather(
        _lookup_db_signals(result.extracted_urls),
        _lookup_rdap_signals(result.extracted_urls),
    )

    extra_signals = [*intel_signals, *rdap_signals]
    if not extra_signals:
        return result

    merged_signals = [*extra_signals, *result.signals]
    score = _combine_weights(merged_signals)
    level = _score_to_level(score)
    summary = _build_summary(level, merged_signals)

    return AnalyzeResponse(
        risk_level=level,
        risk_score=score,
        summary=summary,
        signals=merged_signals,
        extracted_urls=result.extracted_urls,
    )
