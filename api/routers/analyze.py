import re

from fastapi import APIRouter

from api.schemas.analyze import AnalyzeRequest, AnalyzeResponse, RiskLevel

router = APIRouter(prefix="/api/v1", tags=["analyze"])

URL_PATTERN = re.compile(r"https?://[^\s<>\"']+|www\.[^\s<>\"']+", re.IGNORECASE)


@router.post("/analyze", response_model=AnalyzeResponse)
async def analyze_message(payload: AnalyzeRequest) -> AnalyzeResponse:
    """Mesaj ve URL analizi için temel uç nokta (Gün 1 iskeleti).

    Hafta 1-2'de kural motoru, ML sınıflandırıcı, tehdit istihbaratı ve
    LLM ajan katmanı bu uç noktaya bağlanacaktır.
    """
    urls = URL_PATTERN.findall(payload.text)
    return AnalyzeResponse(
        risk_level=RiskLevel.SAFE,
        risk_score=0.0,
        summary="Temel analiz servisi aktif. Kural motoru ve ML sınıflandırıcı henüz bağlı değil.",
        signals=[],
        extracted_urls=urls,
    )
