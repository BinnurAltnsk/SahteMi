from api.schemas.analyze import Channel, RiskLevel
from api.tools.domain import analyze_url, detect_brand_impersonation, extract_urls
from api.tools.rules import analyze_with_rules


def test_official_domains_are_not_flagged() -> None:
    report = analyze_url("https://giris.turkiye.gov.tr/Giris/")
    assert report.is_official is True
    assert report.official_brand == "e-Devlet"
    assert report.signals == []

    bank_report = analyze_url("https://www.ziraatbank.com.tr/tr")
    assert bank_report.is_official is True
    assert bank_report.signals == []


def test_brand_impersonation_and_typosquatting() -> None:
    assert detect_brand_impersonation("ptt-teslimat-bilgi.top") == ("HGS / PTT", "ptt.gov.tr")
    assert detect_brand_impersonation("z1raat-onay.net") == ("Ziraat Bankası", "ziraatbank.com.tr")
    assert detect_brand_impersonation("sahibindenn-odeme.shop") == ("Sahibinden", "sahibinden.com")


def test_extract_urls_strips_trailing_punctuation() -> None:
    urls = extract_urls("Hemen girin: https://hgs-odeme-tr.xyz/sorgula.")
    assert urls == ["https://hgs-odeme-tr.xyz/sorgula"]


def test_detects_phishing_sms_with_fake_ptt_link() -> None:
    res = analyze_with_rules(
        "PTT Kargo: Adres bilginiz eksik. Guncellemek icin tiklayin: https://ptt-teslimat-bilgi.top/adres",
        channel=Channel.SMS,
    )
    assert res.risk_level == RiskLevel.SCAM
    assert res.risk_score >= 0.65
    assert any(s.name == "brand_impersonation" for s in res.signals)


def test_detects_whatsapp_relative_emergency_scam_without_url() -> None:
    res = analyze_with_rules(
        "Anne telefonum bozuldu yeni numaram bu, acil 7.500 TL gondermen lazim. IBAN: [IBAN]",
        channel=Channel.WHATSAPP,
    )
    assert res.risk_level == RiskLevel.SCAM
    assert any(s.name == "relative_emergency_scam" for s in res.signals)


def test_legit_bank_otp_and_fast_are_safe() -> None:
    otp = analyze_with_rules(
        "Akbank 3D Secure: 1.240,00 TL tutarindaki alisverisiniz icin "
        "tek kullanimlik sifreniz 649201.",
        channel=Channel.SMS,
    )
    fast = analyze_with_rules(
        "Garanti BBVA: Hesabiniza 2.500,00 TL FAST transferi gerceklesmistir.",
        channel=Channel.SMS,
    )
    assert otp.risk_level == RiskLevel.SAFE
    assert fast.risk_level == RiskLevel.SAFE
