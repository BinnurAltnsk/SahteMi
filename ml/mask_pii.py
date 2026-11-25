"""KVKK uyumlu kişisel veri (PII) maskeleme modülü.

Mesaj içindeki URL'leri bozmadan IBAN, kart numarası, T.C. kimlik numarası,
telefon numarası ve e-posta adreslerini yer tutucularla değiştirir.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field

URL_RE = re.compile(r"https?://[^\s<>\"']+|www\.[^\s<>\"']+", re.IGNORECASE)
EMAIL_RE = re.compile(r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b")
IBAN_RE = re.compile(r"\bTR\s?\d{2}(?:\s?\d{4}){5}\s?\d{2}\b", re.IGNORECASE)
CARD_RE = re.compile(r"\b(?:\d{4}[-\s]?){3}\d{4}\b")
# Türkiye mobil (+90 5xx / 05xx / 5xx) ve sabit hat (02xx-04xx / 0850) numaraları
PHONE_RE = re.compile(
    r"(?<!\d)(?:(?:\+90|0090|0)\s*[\(\-]?\s*(?:5\d{2}|[234]\d{2}|850)\s*[\)\-]?\s*\d{3}\s*[\-\s]?\d{2}\s*[\-\s]?\d{2})(?!\d)"
)
ELEVEN_DIGITS_RE = re.compile(r"(?<!\d)([1-9]\d{10})(?!\d)")


@dataclass
class MaskResult:
    text: str
    counts: dict[str, int] = field(default_factory=dict)

    @property
    def total_masked(self) -> int:
        return sum(self.counts.values())


def is_valid_tckn(value: str) -> bool:
    """11 haneli T.C. Kimlik Numarası doğrulama algoritması."""
    if len(value) != 11 or not value.isdigit() or value[0] == "0":
        return False
    digits = [int(ch) for ch in value]
    odd_sum = sum(digits[0:9:2])
    even_sum = sum(digits[1:8:2])
    tenth = ((odd_sum * 7) - even_sum) % 10
    eleventh = sum(digits[:10]) % 10
    return digits[9] == tenth and digits[10] == eleventh


def is_valid_luhn(digits: str) -> bool:
    """Kredi/banka kartı numarası için Luhn doğrulama algoritması."""
    if not digits.isdigit() or len(digits) != 16 or digits[0] == "0":
        return False
    total = 0
    for idx, ch in enumerate(reversed(digits)):
        num = int(ch)
        if idx % 2 == 1:
            num *= 2
            if num > 9:
                num -= 9
        total += num
    return total % 10 == 0


def mask_pii(text: str) -> MaskResult:
    """Verilen metindeki kişisel verileri URL'leri koruyarak maskeler."""
    counts: dict[str, int] = {}

    # 1. URL'leri geçici olarak koru (URL içindeki sayılar maskelenmesin)
    url_placeholders: dict[str, str] = {}

    def _stash_url(match: re.Match[str]) -> str:
        key = f"__URL_PLACEHOLDER_{len(url_placeholders)}__"
        url_placeholders[key] = match.group(0)
        return key

    working = URL_RE.sub(_stash_url, text)

    def _replace(pattern: re.Pattern[str], token: str, key: str, source: str) -> str:
        found = 0

        def _sub(_match: re.Match[str]) -> str:
            nonlocal found
            found += 1
            return token

        updated = pattern.sub(_sub, source)
        if found:
            counts[key] = counts.get(key, 0) + found
        return updated

    # 2. Daha spesifik kalıplardan genele doğru maskele
    working = _replace(IBAN_RE, "[IBAN]", "iban", working)
    working = _replace(EMAIL_RE, "[EPOSTA]", "email", working)

    # Kart numarası: yalnızca Luhn'dan geçen ve 0 ile başlamayan 16 haneliler (MERSİS hariç)
    card_count = 0

    def _sub_card(match: re.Match[str]) -> str:
        nonlocal card_count
        raw_digits = re.sub(r"\D", "", match.group(0))
        if is_valid_luhn(raw_digits):
            card_count += 1
            return "[KART_NO]"
        return match.group(0)

    working = CARD_RE.sub(_sub_card, working)
    if card_count:
        counts["card"] = card_count

    working = _replace(PHONE_RE, "[TELEFON]", "phone", working)

    # 3. TCKN: yalnızca checksum doğrulamasından geçen 11 haneli sayıları maskele
    tckn_count = 0

    def _sub_tckn(match: re.Match[str]) -> str:
        nonlocal tckn_count
        candidate = match.group(1)
        if is_valid_tckn(candidate):
            tckn_count += 1
            return "[TCKN]"
        return candidate

    working = ELEVEN_DIGITS_RE.sub(_sub_tckn, working)
    if tckn_count:
        counts["tckn"] = tckn_count

    # 4. URL'leri geri koy
    for key, original_url in url_placeholders.items():
        working = working.replace(key, original_url)

    return MaskResult(text=working, counts=counts)
