from fastapi import APIRouter

from api.schemas.analyze import AnalyzeRequest, AnalyzeResponse
from api.tools.rules import analyze_with_rules

router = APIRouter(prefix="/api/v1", tags=["analyze"])


@router.post("/analyze", response_model=AnalyzeResponse)
async def analyze_message(payload: AnalyzeRequest) -> AnalyzeResponse:
    """Mesaj ve URL analizi uç noktası.

    Alan adı / marka taklidi analizi ile Türkçe sosyal mühendislik
    kurallarını birleştirerek risk skoru ve gerekçeli özet döndürür.
    """
    return analyze_with_rules(payload.text, channel=payload.channel)
