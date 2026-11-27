"""Telegram yanıtları için güvenli HTML biçimlendirici."""

from __future__ import annotations

from html import escape

from api.schemas.analyze import AnalyzeResponse, RiskLevel

_RISK_HEADERS: dict[RiskLevel, str] = {
    RiskLevel.SCAM: "🔴 <b>Yüksek Risk — Dolandırıcılık Şüphesi</b>",
    RiskLevel.SUSPICIOUS: "🟡 <b>Orta Risk — Şüpheli Mesaj</b>",
    RiskLevel.SAFE: "🟢 <b>Düşük Risk — Temiz Görünüyor</b>",
}

_SOURCE_LABELS: dict[str, str] = {
    "url_intel": "Tehdit İstihbaratı",
    "domain": "Alan Adı Analizi",
    "rules": "Kural Motoru",
    "classifier": "Metin Sınıflandırıcı",
}

_SOURCE_ORDER: dict[str, int] = {
    "url_intel": 0,
    "domain": 1,
    "rules": 2,
    "classifier": 3,
}


def format_welcome_message() -> str:
    return (
        "👋 <b>SahteMi'ye Hoş Geldiniz!</b>\n\n"
        "SMS, WhatsApp, Instagram DM veya ilan sitelerinden gelen şüpheli bir mesajı ya da "
        "bağlantıyı bana doğrudan <b>gönderin veya iletin</b>.\n\n"
        "Mesajı Türkçe dolandırıcılık kalıpları, marka taklidi alan adı kontrolleri ve "
        "tehdit istihbaratı listeleriyle analiz edip gerekçeli risk sonucunu paylaşırım.\n\n"
        "Komutlar için /yardim yazabilirsiniz."
    )


def format_help_message() -> str:
    return (
        "ℹ️ <b>SahteMi Kullanım Rehberi</b>\n\n"
        "• Şüpheli bir mesajı veya linki doğrudan sohbete yapıştırın ya da iletin.\n"
        "• İsterseniz mesajın geldiği kanalı komutla belirtebilirsiniz:\n"
        "  <code>/sms</code> mesaj metni\n"
        "  <code>/whatsapp</code> mesaj metni\n"
        "  <code>/instagram</code> mesaj metni\n"
        "  <code>/ilan</code> mesaj metni\n\n"
        "<b>Diğer Komutlar:</b>\n"
        "• /start — Karşılama mesajı\n"
        "• /istatistik — Güncel tehdit istihbaratı kayıt sayıları\n"
        "• /yardim — Bu yardım mesajı\n\n"
        "<i>Not: Analiz sonucu bilgilendirme amaçlıdır. Şüpheli bağlantılara tıklamayın ve "
        "şifre/kart bilgilerinizi paylaşmayın.</i>"
    )


def format_analysis_result(result: AnalyzeResponse) -> str:
    header = _RISK_HEADERS.get(result.risk_level, "⚪ <b>Analiz Sonucu</b>")
    score_pct = round(result.risk_score * 100)

    lines = [
        header,
        f"<b>Risk Skoru:</b> %{score_pct}",
        "",
        escape(result.summary),
    ]

    if result.signals:
        lines.append("")
        lines.append("<b>Tespit Edilen Sinyaller:</b>")
        ordered_signals = sorted(
            result.signals,
            key=lambda s: (_SOURCE_ORDER.get(s.source, 99), -s.weight),
        )
        for signal in ordered_signals[:8]:
            source_label = _SOURCE_LABELS.get(signal.source, signal.source)
            lines.append(f"• <b>{escape(source_label)}:</b> {escape(signal.detail)}")

    if result.extracted_urls:
        lines.append("")
        lines.append("<b>İncelenen Bağlantılar:</b>")
        for url in result.extracted_urls[:5]:
            # <code> etiketi Telegram'ın bağlantıyı otomatik tıklanabilir yapmasını engeller
            lines.append(f"• <code>{escape(url)}</code>")

    if result.risk_level in {RiskLevel.SCAM, RiskLevel.SUSPICIOUS}:
        lines.append("")
        lines.append(
            "⚠️ <i>Öneri: Bağlantılara tıklamayın, doğrulama kodu veya kart bilgisi paylaşmayın. "
            "Resmi kurum işlemlerini yalnızca resmi uygulama veya tarayıcıdan kendiniz yazarak "
            "kontrol edin.</i>"
        )

    return "\n".join(lines)


def format_stats_message(stats: dict[str, int | str]) -> str:
    if stats.get("status") == "db_unavailable":
        return "⚠️ Tehdit istihbaratı veritabanına şu anda ulaşılamıyor."

    total = stats.get("total", 0)
    lines = [
        "📊 <b>SahteMi Tehdit İstihbaratı Özeti</b>",
        "",
        f"• <b>Toplam Kayıt:</b> {escape(str(total))}",
    ]

    for key, value in sorted(stats.items()):
        if key in {"total", "status"}:
            continue
        lines.append(f"• <b>{escape(str(key))}:</b> {escape(str(value))}")

    return "\n".join(lines)
