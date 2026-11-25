from enum import StrEnum

from pydantic import BaseModel, Field


class RiskLevel(StrEnum):
    SAFE = "safe"
    SUSPICIOUS = "suspicious"
    SCAM = "scam"


class Channel(StrEnum):
    SMS = "sms"
    WHATSAPP = "whatsapp"
    INSTAGRAM = "instagram"
    CLASSIFIEDS = "classifieds"
    OTHER = "other"


class SignalItem(BaseModel):
    source: str = Field(
        ..., description="Sinyali üreten araç (rules, classifier, url_intel, domain)"
    )
    name: str = Field(..., description="Sinyal adı")
    detail: str = Field(..., description="Kullanıcıya yönelik kısa Türkçe açıklama")
    weight: float = Field(..., ge=0.0, le=1.0, description="Risk ağırlığı (0-1)")


class AnalyzeRequest(BaseModel):
    text: str = Field(
        ..., min_length=3, max_length=4000, description="Analiz edilecek mesaj veya URL"
    )
    channel: Channel = Field(default=Channel.OTHER, description="Mesajın geldiği kanal")


class AnalyzeResponse(BaseModel):
    risk_level: RiskLevel
    risk_score: float = Field(..., ge=0.0, le=1.0)
    summary: str = Field(..., description="Türkçe gerekçeli özet")
    signals: list[SignalItem] = Field(default_factory=list)
    extracted_urls: list[str] = Field(default_factory=list)
