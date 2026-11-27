from types import SimpleNamespace
from unittest.mock import AsyncMock

import httpx
import pytest

from api.schemas.analyze import AnalyzeResponse, Channel, RiskLevel, SignalItem
from bot.client import ApiClientError, SahteMiApiClient
from bot.config import BotSettings
from bot.formatter import (
    format_analysis_result,
    format_help_message,
    format_stats_message,
    format_welcome_message,
)
from bot.handlers import (
    MAX_TEXT_LENGTH,
    analyze_message_handler,
    extract_channel_and_text,
    stats_command,
)
from bot.main import build_application


def test_extract_channel_and_text() -> None:
    assert extract_channel_and_text("Normal şüpheli mesaj") == (
        Channel.OTHER,
        "Normal şüpheli mesaj",
    )
    assert extract_channel_and_text("/sms Kargonuz bekliyor https://ptt-kargo.xyz") == (
        Channel.SMS,
        "Kargonuz bekliyor https://ptt-kargo.xyz",
    )
    assert extract_channel_and_text("/whatsapp@SahteMiBot Anne telefonum bozuldu") == (
        Channel.WHATSAPP,
        "Anne telefonum bozuldu",
    )
    assert extract_channel_and_text("/ilan Param güvende linki") == (
        Channel.CLASSIFIEDS,
        "Param güvende linki",
    )
    assert extract_channel_and_text("/sms") == (Channel.SMS, "")


def test_format_analysis_result_escapes_html_and_wraps_urls() -> None:
    response = AnalyzeResponse(
        risk_level=RiskLevel.SCAM,
        risk_score=0.95,
        summary="Sahte <script>alert(1)</script> PTT kargo bağlantısı.",
        signals=[
            SignalItem(
                source="url_intel",
                name="known_malicious_url",
                detail="Bilinen oltalama bağlantısı (openphish).",
                weight=0.95,
            ),
            SignalItem(
                source="rules",
                name="urgency",
                detail="Aciliyet baskısı tespit edildi.",
                weight=0.4,
            ),
        ],
        extracted_urls=["https://ptt-takip.xyz/odeme?a=1&b=2"],
    )

    formatted = format_analysis_result(response)
    assert "🔴 <b>Yüksek Risk" in formatted
    assert "%95" in formatted
    assert "&lt;script&gt;alert(1)&lt;/script&gt;" in formatted
    assert "<code>https://ptt-takip.xyz/odeme?a=1&amp;b=2</code>" in formatted
    assert "Tehdit İstihbaratı" in formatted
    assert "Kural Motoru" in formatted
    assert "Bağlantılara tıklamayın" in formatted


def test_format_safe_and_stats_messages() -> None:
    safe_response = AnalyzeResponse(
        risk_level=RiskLevel.SAFE,
        risk_score=0.05,
        summary="Belirgin bir risk sinyali bulunamadı.",
    )
    safe_text = format_analysis_result(safe_response)
    assert "🟢 <b>Düşük Risk" in safe_text
    assert "Bağlantılara tıklamayın" not in safe_text

    stats_text = format_stats_message({"openphish": 300, "urlhaus": 120, "total": 420})
    assert "420" in stats_text
    assert "openphish" in stats_text

    unavailable_text = format_stats_message({"status": "db_unavailable", "total": 0})
    assert "ulaşılamıyor" in unavailable_text
    assert "SahteMi" in format_welcome_message()
    assert "/istatistik" in format_help_message()


@pytest.mark.asyncio
async def test_api_client_analyze_and_stats_success() -> None:
    def handler(request: httpx.Request) -> httpx.Response:
        if request.url.path == "/api/v1/analyze":
            return httpx.Response(
                200,
                json={
                    "risk_level": "scam",
                    "risk_score": 0.92,
                    "summary": "Yüksek riskli oltalama.",
                    "signals": [],
                    "extracted_urls": ["https://sahte-ptt.xyz"],
                },
            )
        if request.url.path == "/api/v1/threats/stats":
            return httpx.Response(200, json={"openphish": 300, "total": 300})
        return httpx.Response(404)

    client = SahteMiApiClient(
        base_url="http://testserver",
        transport=httpx.MockTransport(handler),
    )

    result = await client.analyze("Kargonuz bekliyor https://sahte-ptt.xyz", channel=Channel.SMS)
    assert result.risk_level == RiskLevel.SCAM
    assert result.risk_score == 0.92

    stats = await client.get_threat_stats()
    assert stats["total"] == 300


@pytest.mark.asyncio
async def test_api_client_raises_on_http_error() -> None:
    def handler(_request: httpx.Request) -> httpx.Response:
        return httpx.Response(503, text="Service Unavailable")

    client = SahteMiApiClient(
        base_url="http://testserver",
        transport=httpx.MockTransport(handler),
    )
    with pytest.raises(ApiClientError, match="HTTP 503"):
        await client.analyze("Şüpheli mesaj metni")


@pytest.mark.asyncio
async def test_analyze_message_handler_flows() -> None:
    mock_api = AsyncMock(spec=SahteMiApiClient)
    mock_api.analyze.return_value = AnalyzeResponse(
        risk_level=RiskLevel.SUSPICIOUS,
        risk_score=0.65,
        summary="Şüpheli ödeme bağlantısı.",
        extracted_urls=["https://ornek.xyz"],
    )
    mock_api.get_threat_stats.return_value = {"openphish": 300, "total": 300}

    context = SimpleNamespace(
        application=SimpleNamespace(bot_data={"api_client": mock_api}),
        bot=SimpleNamespace(send_chat_action=AsyncMock()),
    )

    # 1. Çok kısa mesaj reddedilmeli ve API çağrılmamalı
    short_msg = SimpleNamespace(text="ab", caption=None, reply_text=AsyncMock())
    short_update = SimpleNamespace(message=short_msg, effective_chat=SimpleNamespace(id=1))
    await analyze_message_handler(short_update, context)
    mock_api.analyze.assert_not_awaited()
    assert "en az 3 karakter" in short_msg.reply_text.call_args.args[0]

    # 2. Kanal komutu ile uzun mesaj kesilip analiz edilmeli
    long_body = "a" * (MAX_TEXT_LENGTH + 50)
    long_msg = SimpleNamespace(text=f"/sms {long_body}", caption=None, reply_text=AsyncMock())
    long_update = SimpleNamespace(message=long_msg, effective_chat=SimpleNamespace(id=1))
    await analyze_message_handler(long_update, context)
    called_text = mock_api.analyze.call_args.args[0]
    called_channel = mock_api.analyze.call_args.kwargs["channel"]
    assert len(called_text) == MAX_TEXT_LENGTH
    assert called_channel == Channel.SMS
    assert "ilk 4000 karakter" in long_msg.reply_text.call_args.args[0]

    # 3. İstatistik komutu
    stats_msg = SimpleNamespace(reply_text=AsyncMock())
    stats_update = SimpleNamespace(message=stats_msg)
    await stats_command(stats_update, context)
    assert "300" in stats_msg.reply_text.call_args.args[0]


def test_build_application_requires_token() -> None:
    with pytest.raises(ValueError, match="TELEGRAM_BOT_TOKEN"):
        build_application(BotSettings(telegram_bot_token=""))
