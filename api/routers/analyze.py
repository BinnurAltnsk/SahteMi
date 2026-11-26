from fastapi import APIRouter

from api.db.session import get_session_factory
from api.schemas.analyze import AnalyzeRequest, AnalyzeResponse
from api.tools.rules import (
    _build_summary,
    _combine_weights,
    _score_to_level,
    analyze_with_rules,
)
from api.tools.url_intel import check_urls_in_db

router = APIRouter(prefix="/api/v1", tags=["analyze"])


@router.post("/analyze", response_model=AnalyzeResponse)
async def analyze_message(payload: AnalyzeRequest) -> AnalyzeResponse:
    """Mesaj ve URL analizi uç noktası.

    Alan adı / marka taklidi analizi, Türkçe sosyal mühendislik kuralları ve
    PostgreSQL'deki tehdit istihbaratı beslemelerini (OpenPhish, URLhaus)
    birleştirerek risk skoru ve gerekçeli özet döndürür.
    """
    result = analyze_with_rules(payload.text, channel=payload.channel)
    if not result.extracted_urls:
        return result

    intel_signals = []
    try:
        factory = get_session_factory()
        async with factory() as session:
            intel_signals = await check_urls_in_db(result.extracted_urls, session)
    except Exception:  # noqa: BLE001
        intel_signals = []

    if not intel_signals:
        return result

    merged_signals = [*intel_signals, *result.signals]
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
