"""Türkçe dolandırıcılık ve sosyal mühendislik kural motoru.

Alan adı analizi (`api.tools.domain`) ile metin içi sosyal mühendislik
sinyallerini birleştirip açıklanabilir risk skoru ve Türkçe özet üretir.
"""

from __future__ import annotations

import re

from api.schemas.analyze import AnalyzeResponse, Channel, RiskLevel, SignalItem
from api.tools.domain import OFFICIAL_BRANDS, analyze_url, extract_urls, normalize_for_brand_check

# Sosyal mühendislik & aciliyet kalıpları
URGENCY_THREAT_RE = re.compile(
    r"\b(bloke|askiya\s+alindi|kapatilacaktir|icra|yasal\s+takip|haciz|"
    r"ceza\s+odenmemistir|24\s+saat\s+icinde|2\s+saat\s+icinde|kesinti\s+yapilacaktir|"
    r"son\s+gun|son\s+odeme\s+gunudur|iade\s+edilecektir|iade\s+olacak)\b",
    re.IGNORECASE,
)

ACTION_BAIT_RE = re.compile(
    r"\b(tiklayin|giris\s+yapin|dogrulayin|guncelleyin|formu\s+doldurun|"
    r"kartinizi\s+girip|kart\s+bilgilerinizi|iban\s+bilgilerinizi|"
    r"hemen\s+odeme|hemen\s+tiklayin|nakde\s+cevirmek)\b",
    re.IGNORECASE,
)

# WhatsApp yakın taklidi / acil para isteme
FAMILY_MONEY_RE = re.compile(
    r"\b(anne|baba|kuzen|kuzenim|kuzeninim|abim|ablam|yeni\s+numaram|telefonum\s+bozuldu)\b",
    re.IGNORECASE,
)
MONEY_REQUEST_RE = re.compile(
    r"\b(acil|limit\s+dolu|gondermen\s+lazim|atabilir\s+misin|iban|tl\s+gonder|tl\s+at)\b",
    re.IGNORECASE,
)

# İlan / kurye / Param Güvende dolandırıcılığı
CLASSIFIEDS_SCAM_RE = re.compile(
    r"\b(param\s+guvende|kurye\s+odeme\s+link|kurye\s+ile\s+aldiracagim|"
    r"kartinizi\s+girip\s+parayi|parayi\s+hesabiniza\s+cekmek\s+icin\s+kart)\b",
    re.IGNORECASE,
)

# Sahte kolay kazanç / kripto / yatırım vaadi
EASY_MONEY_RE = re.compile(
    r"\b(garantili\s+getiri|gunde\s+\d+\s+saat\s+calisarak|gorevleri\s+tamamla|"
    r"aninda\s+hesabina\s+yatsin|vip\s+sinyal|yapay\s+zeka\s+botumuzla)\b",
    re.IGNORECASE,
)

# Sahte çekiliş / ön ödeme tuzağı
GIVEAWAY_FEE_RE = re.compile(
    r"\b(cekilis|hediye\s+ceki|alisveris\s+ceki|iphone\s+\d+\s+kazandiniz|kazandiniz)\b",
    re.IGNORECASE,
)
ADVANCE_FEE_RE = re.compile(
    r"\b(kargo\s+sigorta\s+ucreti|sigorta\s+ucreti|iban\s+isteyiniz|gumruk\s+vergisi)\b",
    re.IGNORECASE,
)

# Sahte hukuk / icra telefon yönlendirmesi
LEGAL_CALL_SCAM_RE = re.compile(
    r"\b(icra\s+dosyasi|tazminat\s+davasi|uzlasma\s+saglamak|dosya\s+kapatma)\b",
    re.IGNORECASE,
)
PHONE_HINT_RE = re.compile(
    r"(\[TELEFON\]|(?:\+90|0)\s*\(?\d{3}\)?\s*\d{3}\s*\d{2}\s*\d{2})",
    re.IGNORECASE,
)

# Bilgilendirme amaçlı, aksiyon/link istemeyen resmi bildirim kalıpları
SAFE_INFO_RE = re.compile(
    r"\b(tek\s+kullanimlik\s+sifreniz|3d\s+secure|fast\s+transferi\s+gerceklesmistir|"
    r"tutarinda\s+harcama\s+yapilmistir|randevunuz\s+bulunmaktadir|"
    r"resmi\s+uygulama\s+uzerinden|mobil\s+bankaciliktan\s+inceleyebilirsiniz|"
    r"teslim\s+edilmistir|dagitima\s+cikmistir|dagitim\s+merkezine\s+ulasmistir)\b",
    re.IGNORECASE,
)


def _detect_mentioned_brands(norm_text: str) -> list[str]:
    found: list[str] = []
    for brand, (_domains, keywords) in OFFICIAL_BRANDS.items():
        for kw in keywords:
            norm_kw = normalize_for_brand_check(kw)
            if len(norm_kw) >= 3 and re.search(rf"\b{re.escape(norm_kw)}\b", norm_text):
                found.append(brand)
                break
    return found


def _combine_weights(signals: list[SignalItem]) -> float:
    """Bağımsız sinyalleri olasılıksal birleşimle (noisy-OR) 0-1 aralığına sıkıştırır."""
    remaining_safe = 1.0
    for sig in signals:
        remaining_safe *= 1.0 - sig.weight
    return round(min(1.0, max(0.0, 1.0 - remaining_safe)), 3)


def _score_to_level(score: float) -> RiskLevel:
    if score >= 0.65:
        return RiskLevel.SCAM
    if score >= 0.35:
        return RiskLevel.SUSPICIOUS
    return RiskLevel.SAFE


def _build_summary(level: RiskLevel, signals: list[SignalItem]) -> str:
    if not signals:
        return "Mesajda belirgin bir dolandırıcılık veya oltalama sinyali tespit edilmedi."

    top_reasons = " ".join(
        sig.detail for sig in sorted(signals, key=lambda s: s.weight, reverse=True)[:3]
    )
    if level == RiskLevel.SCAM:
        return f"Yüksek dolandırıcılık riski: {top_reasons}"
    if level == RiskLevel.SUSPICIOUS:
        return f"Şüpheli sinyaller tespit edildi: {top_reasons}"
    return f"Düşük riskli sinyal bulundu ancak belirgin dolandırıcılık görülmedi: {top_reasons}"


def analyze_with_rules(text: str, channel: Channel = Channel.OTHER) -> AnalyzeResponse:
    """Metni alan adı ve Türkçe sosyal mühendislik kurallarıyla analiz eder."""
    urls = extract_urls(text)
    norm_text = normalize_for_brand_check(text)
    signals: list[SignalItem] = []

    # 1. URL / alan adı analizi
    has_unverified_url = False
    for url in urls:
        report = analyze_url(url)
        signals.extend(report.signals)
        if report.host and not report.is_official:
            has_unverified_url = True

    # 2. Metinde bilinen Türk markası/kurumu + doğrulanmamış link
    mentioned_brands = _detect_mentioned_brands(norm_text)
    already_impersonated = any(s.name == "brand_impersonation" for s in signals)
    if mentioned_brands and has_unverified_url and not already_impersonated:
        brands_str = ", ".join(mentioned_brands[:2])
        signals.append(
            SignalItem(
                source="rules",
                name="brand_with_unverified_url",
                detail=(
                    f"Mesajda {brands_str} adı geçiyor ancak bağlantı resmi kuruma ait görünmüyor."
                ),
                weight=0.60,
            )
        )

    # 3. Aciliyet / tehdit + aksiyon çağrısı
    has_urgency = bool(URGENCY_THREAT_RE.search(norm_text))
    has_action = bool(ACTION_BAIT_RE.search(norm_text))
    if has_urgency and (has_unverified_url or has_action):
        signals.append(
            SignalItem(
                source="rules",
                name="urgency_pressure",
                detail=(
                    "Bloke, icra, ceza veya süre baskısı yaratarak acele işlem "
                    "yaptırmaya çalışıyor."
                ),
                weight=0.45,
            )
        )
    elif has_action and has_unverified_url:
        signals.append(
            SignalItem(
                source="rules",
                name="credential_or_payment_bait",
                detail=(
                    "Doğrulanmamış bir bağlantı üzerinden giriş, kart veya kimlik bilgisi istiyor."
                ),
                weight=0.45,
            )
        )

    # 4. WhatsApp yakın taklidi / acil para isteme
    if FAMILY_MONEY_RE.search(norm_text) and MONEY_REQUEST_RE.search(norm_text):
        signals.append(
            SignalItem(
                source="rules",
                name="relative_emergency_scam",
                detail="Yakın/akraba taklidiyle acil para veya IBAN transferi isteniyor.",
                weight=0.75,
            )
        )

    # 5. İlan / kurye / Param Güvende dolandırıcılığı
    if CLASSIFIEDS_SCAM_RE.search(norm_text):
        signals.append(
            SignalItem(
                source="rules",
                name="classifieds_payment_scam",
                detail=(
                    "İlan/kurye ödeme bahanesiyle sahte ödeme linkine veya kart "
                    "girişine yönlendiriyor."
                ),
                weight=0.75,
            )
        )

    # 6. Kolay kazanç / garantili yatırım / kripto botu
    if EASY_MONEY_RE.search(norm_text):
        signals.append(
            SignalItem(
                source="rules",
                name="easy_money_investment_scam",
                detail="Gerçekçi olmayan kolay kazanç veya garantili yatırım getirisi vaat ediyor.",
                weight=0.75,
            )
        )

    # 7. Sahte çekiliş / ön ödeme
    if GIVEAWAY_FEE_RE.search(norm_text) and (
        ADVANCE_FEE_RE.search(norm_text) or has_unverified_url
    ):
        signals.append(
            SignalItem(
                source="rules",
                name="giveaway_or_advance_fee_scam",
                detail="Çekiliş/hediye vaadiyle ön ücret, IBAN veya harici form istiyor.",
                weight=0.70,
            )
        )

    # 8. Sahte icra / dava + telefon yönlendirmesi (linksiz SMS dolandırıcılığı)
    if LEGAL_CALL_SCAM_RE.search(norm_text) and (
        PHONE_HINT_RE.search(text) or has_urgency or has_unverified_url
    ):
        signals.append(
            SignalItem(
                source="rules",
                name="fake_legal_threat",
                detail="Sahte icra/dava bildirimiyle panik yaratarak iletişim veya ödeme istiyor.",
                weight=0.70,
            )
        )

    # 9. Güvenli bilgilendirme kontrolü: link yoksa, para/kart istemiyorsa yanlış alarmı önle
    if not urls and not signals and SAFE_INFO_RE.search(norm_text):
        return AnalyzeResponse(
            risk_level=RiskLevel.SAFE,
            risk_score=0.05,
            summary="Bağlantı veya bilgi talebi içermeyen standart bilgilendirme mesajı görünüyor.",
            signals=[],
            extracted_urls=[],
        )

    # Kanal bazlı küçük bağlam notu (şimdilik skoru şişirmeden korunur)
    _ = channel
    score = _combine_weights(signals)
    level = _score_to_level(score)
    summary = _build_summary(level, signals)

    return AnalyzeResponse(
        risk_level=level,
        risk_score=score,
        summary=summary,
        signals=signals,
        extracted_urls=urls,
    )
