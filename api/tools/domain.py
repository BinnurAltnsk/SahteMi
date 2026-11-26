"""Alan adı analizi ve Türk marka/kurum taklidi (typosquatting/impersonation) tespiti."""

from __future__ import annotations

import re
from dataclasses import dataclass
from urllib.parse import urlparse

from api.schemas.analyze import SignalItem

URL_PATTERN = re.compile(r"https?://[^\s<>\"']+|www\.[^\s<>\"']+", re.IGNORECASE)
IPV4_HOST_RE = re.compile(r"^(?:\d{1,3}\.){3}\d{1,3}$")

# Resmi Türk kurumları, bankalar, kargo ve büyük platformlar:
# marka_adi -> (resmi_alan_adlari, metin/alan_adi_anahtar_kelimeleri)
OFFICIAL_BRANDS: dict[str, tuple[tuple[str, ...], tuple[str, ...]]] = {
    "e-Devlet": (("turkiye.gov.tr",), ("edevlet", "e-devlet", "turkiyegov")),
    "GİB": (("gib.gov.tr",), ("gib", "vergidaire", "geliridaresi")),
    "HGS / PTT": (
        ("ptt.gov.tr", "hgsmusteri.ptt.gov.tr", "pttavm.com"),
        ("ptt", "hgs", "gumruk-ptt"),
    ),
    "UYAP": (("uyap.gov.tr", "adalet.gov.tr"), ("uyap",)),
    "e-Nabız": (("enabiz.gov.tr",), ("enabiz", "e-nabiz")),
    "MHRS": (("mhrs.gov.tr",), ("mhrs",)),
    "Aile ve Sosyal Hizmetler": (("aile.gov.tr",), ("aile-sosyal", "sosyal-destek")),
    "Ziraat Bankası": (("ziraatbank.com.tr",), ("ziraat",)),
    "Garanti BBVA": (("garantibbva.com.tr",), ("garanti", "garantibbva")),
    "Akbank": (("akbank.com",), ("akbank",)),
    "İş Bankası": (("isbank.com.tr",), ("isbank", "isbankasi")),
    "Yapı Kredi": (("yapikredi.com.tr",), ("yapikredi",)),
    "VakıfBank": (("vakifbank.com.tr",), ("vakifbank",)),
    "Halkbank": (("halkbank.com.tr",), ("halkbank",)),
    "QNB": (("qnb.com.tr", "qnbfinansbank.com"), ("qnbfinans", "finansbank")),
    "DenizBank": (("denizbank.com",), ("denizbank",)),
    "Yurtiçi Kargo": (("yurticikargo.com",), ("yurtici",)),
    "MNG Kargo": (("mngkargo.com.tr",), ("mng", "mngkargo")),
    "Aras Kargo": (("araskargo.com.tr",), ("araskargo",)),
    "Sürat Kargo": (("suratkargo.com.tr",), ("suratkargo",)),
    "Trendyol": (("trendyol.com", "trendyolexpress.com"), ("trendyol",)),
    "Sahibinden": (("sahibinden.com",), ("sahibinden", "paramguvende")),
    "Dolap": (("dolap.com",), ("dolap",)),
    "Hepsiburada": (("hepsiburada.com",), ("hepsiburada",)),
    "A101": (("a101.com.tr",), ("a101",)),
    "BİM": (("bim.com.tr",), ("bim-hediye", "bimmarket")),
    "Turkcell": (("turkcell.com.tr",), ("turkcell",)),
    "Türk Telekom": (("turktelekom.com.tr",), ("turktelekom",)),
    "Vodafone": (("vodafone.com.tr",), ("vodafone",)),
    "CK Boğaziçi": (("ckbogazici.com.tr",), ("ckbogazici",)),
    "Netflix": (("netflix.com",), ("netflix",)),
    "Instagram": (("instagram.com",), ("instagram",)),
}

SUSPICIOUS_TLDS: set[str] = {
    "xyz",
    "top",
    "click",
    "shop",
    "site",
    "online",
    "buzz",
    "info",
    "icu",
    "vip",
    "tk",
    "ml",
    "ga",
    "cf",
    "gq",
    "work",
    "loan",
    "live",
}

URL_SHORTENERS: set[str] = {
    "bit.ly",
    "tinyurl.com",
    "t.co",
    "cutt.ly",
    "rb.gy",
    "is.gd",
    "shorturl.at",
    "goo.gl",
    "ow.ly",
    "tiny.cc",
}

# Görsel olarak benzeyen karakter (homoglyph / leetspeak) normalizasyonu
HOMOGLYPH_MAP = str.maketrans(
    {
        "0": "o",
        "1": "i",
        "3": "e",
        "4": "a",
        "5": "s",
        "7": "t",
        "ı": "i",
        "İ": "i",
        "ğ": "g",
        "ü": "u",
        "ş": "s",
        "ö": "o",
        "ç": "c",
    }
)


@dataclass
class DomainReport:
    url: str
    host: str
    is_official: bool
    official_brand: str | None
    signals: list[SignalItem]


def extract_urls(text: str) -> list[str]:
    """Metin içindeki URL'leri temizleyerek çıkarır."""
    raw = URL_PATTERN.findall(text)
    cleaned: list[str] = []
    for item in raw:
        trimmed = item.rstrip(".,;:!?)")
        if trimmed and trimmed not in cleaned:
            cleaned.append(trimmed)
    return cleaned


def parse_host(url: str) -> str:
    """URL'den küçük harfli alan adını (hostname) çıkarır."""
    candidate = url if re.match(r"^https?://", url, re.IGNORECASE) else f"https://{url}"
    parsed = urlparse(candidate)
    host = (parsed.hostname or "").lower().strip(".")
    return host


def is_subdomain_or_exact(host: str, official_domain: str) -> bool:
    return host == official_domain or host.endswith(f".{official_domain}")


def normalize_for_brand_check(value: str) -> str:
    return value.lower().translate(HOMOGLYPH_MAP)


def levenshtein_distance(a: str, b: str) -> int:
    if len(a) < len(b):
        a, b = b, a
    if not b:
        return len(a)
    prev = list(range(len(b) + 1))
    for i, ch_a in enumerate(a, start=1):
        curr = [i]
        for j, ch_b in enumerate(b, start=1):
            cost = 0 if ch_a == ch_b else 1
            curr.append(min(prev[j] + 1, curr[j - 1] + 1, prev[j - 1] + cost))
        prev = curr
    return prev[-1]


def find_official_brand(host: str) -> str | None:
    for brand, (domains, _keywords) in OFFICIAL_BRANDS.items():
        if any(is_subdomain_or_exact(host, dom) for dom in domains):
            return brand
    return None


def detect_brand_impersonation(host: str) -> tuple[str, str] | None:
    """Resmi olmayan bir alan adında Türk marka/kurum taklidi arar."""
    if find_official_brand(host) is not None:
        return None

    # Alan adını parçalara ayır (TLD hariç)
    labels = host.split(".")
    host_body = ".".join(labels[:-1]) if len(labels) > 1 else host
    norm_body = normalize_for_brand_check(host_body)
    tokens = [tok for tok in re.split(r"[-._]", norm_body) if tok]

    for brand, (official_domains, keywords) in OFFICIAL_BRANDS.items():
        for kw in keywords:
            norm_kw = normalize_for_brand_check(kw)
            # 1. Doğrudan veya tireli geçiş (ör. ptt-teslimat-bilgi, ziraat-guvenlik-onay)
            if len(norm_kw) >= 4 and norm_kw in norm_body:
                return brand, official_domains[0]
            if norm_kw in tokens:
                return brand, official_domains[0]

            # 2. Yakın yazım hatası / typosquatting (uzunluğu >= 5 olan anahtar kelimelerde)
            if len(norm_kw) >= 5:
                for tok in tokens:
                    if (
                        abs(len(tok) - len(norm_kw)) <= 1
                        and levenshtein_distance(tok, norm_kw) == 1
                    ):
                        return brand, official_domains[0]

    return None


def analyze_url(url: str) -> DomainReport:
    """Tek bir URL için alan adı ve marka taklidi sinyallerini üretir."""
    host = parse_host(url)
    signals: list[SignalItem] = []

    if not host:
        return DomainReport(
            url=url, host="", is_official=False, official_brand=None, signals=signals
        )

    official_brand = find_official_brand(host)
    if official_brand is not None:
        return DomainReport(
            url=url,
            host=host,
            is_official=True,
            official_brand=official_brand,
            signals=signals,
        )

    # 1. Marka / kurum taklidi
    impersonated = detect_brand_impersonation(host)
    if impersonated is not None:
        brand, official_domain = impersonated
        signals.append(
            SignalItem(
                source="domain",
                name="brand_impersonation",
                detail=(
                    f"'{host}' adresi {brand} adını taklit ediyor (resmi adres: {official_domain})."
                ),
                weight=0.75,
            )
        )

    # 2. IP adresi üzerinden bağlantı
    if IPV4_HOST_RE.match(host):
        signals.append(
            SignalItem(
                source="domain",
                name="ip_address_url",
                detail=f"Bağlantı alan adı yerine doğrudan IP adresi ({host}) kullanıyor.",
                weight=0.55,
            )
        )

    # 3. Punycode / IDN homograph
    if "xn--" in host:
        signals.append(
            SignalItem(
                source="domain",
                name="punycode_homograph",
                detail=f"'{host}' adresi görsel aldatmaca (IDN/punycode) içerebilir.",
                weight=0.50,
            )
        )

    # 4. Kısaltılmış URL
    if host in URL_SHORTENERS:
        signals.append(
            SignalItem(
                source="domain",
                name="url_shortener",
                detail=f"'{host}' kısaltılmış bir bağlantı; gerçek hedef adres gizleniyor.",
                weight=0.35,
            )
        )

    # 5. Dolandırıcılıkta sık kullanılan uzantılar (TLD)
    tld = host.rsplit(".", maxsplit=1)[-1] if "." in host else ""
    if tld in SUSPICIOUS_TLDS:
        signals.append(
            SignalItem(
                source="domain",
                name="suspicious_tld",
                detail=(
                    f"'.{tld}' uzantısı oltalama saldırılarında sık kullanılan "
                    "riskli bir uzantıdır."
                ),
                weight=0.30,
            )
        )

    # 6. Alan adında çok fazla tire + kimlik avı kelimesi
    phish_words = (
        "odeme",
        "onay",
        "guncelle",
        "dogrula",
        "sorgu",
        "iade",
        "ceza",
        "tahsilat",
        "sifre",
    )
    norm_host = normalize_for_brand_check(host)
    if host.count("-") >= 2 and any(w in norm_host for w in phish_words):
        signals.append(
            SignalItem(
                source="domain",
                name="phishing_domain_pattern",
                detail=f"'{host}' alan adı çoklu tire ve işlem/ödeme anahtar kelimesi içeriyor.",
                weight=0.35,
            )
        )

    return DomainReport(
        url=url,
        host=host,
        is_official=False,
        official_brand=None,
        signals=signals,
    )
