"""TurkishSMSCollection keşifsel veri analizi (EDA) ve temizleme scripti.

Kullanım:
    python -m ml.eda
"""

from __future__ import annotations

import csv
import re
from collections import Counter
from pathlib import Path
from statistics import median

from ml.mask_pii import URL_RE, mask_pii

ROOT_DIR = Path(__file__).resolve().parent.parent
RAW_CSV = ROOT_DIR / "ml" / "data" / "raw" / "TurkishSMSCollection.csv"
PROCESSED_CSV = ROOT_DIR / "ml" / "data" / "processed" / "turkish_sms_clean.csv"
REPORT_MD = ROOT_DIR / "ml" / "notebooks" / "01_eda_report.md"

URGENCY_RE = re.compile(
    r"\b(acil|hemen|son\s+gun|son\s+gün|bloke|icra|ceza|teslim\s+edilemedi|"
    r"onay|tıklayın|tiklayin|hediye|kazandınız|kazandiniz|fırsat|firsat|ücretsiz|ucretsiz)\b",
    re.IGNORECASE,
)


def load_raw_rows(path: Path) -> tuple[list[tuple[str, str]], int]:
    """Ham CSV dosyasını güvenli biçimde okur, bozuk satırları sayar."""
    rows: list[tuple[str, str]] = []
    malformed = 0

    with path.open("r", encoding="utf-8-sig", newline="") as handle:
        reader = csv.reader(handle, delimiter=";")
        header = next(reader, None)
        if not header:
            return rows, malformed

        for parts in reader:
            if len(parts) < 3:
                malformed += 1
                continue
            # Mesaj içinde tırnaksız ';' geçtiyse baştaki parçaları birleştir
            message = ";".join(parts[:-2]).strip()
            group_text = parts[-1].strip().lower()
            if not message or group_text not in {"spam", "normal"}:
                malformed += 1
                continue
            rows.append((message, group_text))

    return rows, malformed


def run_eda() -> None:
    if not RAW_CSV.exists():
        raise FileNotFoundError(f"Ham veri seti bulunamadı: {RAW_CSV}")

    raw_rows, malformed = load_raw_rows(RAW_CSV)
    total_raw = len(raw_rows)

    seen_keys: set[tuple[str, str]] = set()
    cleaned_records: list[dict[str, str]] = []
    pii_totals: Counter[str] = Counter()
    duplicate_count = 0

    for message, label in raw_rows:
        dedup_key = (message.lower(), label)
        if dedup_key in seen_keys:
            duplicate_count += 1
            continue
        seen_keys.add(dedup_key)

        masked = mask_pii(message)
        pii_totals.update(masked.counts)
        cleaned_records.append(
            {
                "id": f"trsms_{len(cleaned_records) + 1:05d}",
                "text_masked": masked.text,
                "label": label,
                "source": "TurkishSMSCollection_2021",
                "year": "2021",
            }
        )

    # Temizlenmiş CSV yaz
    PROCESSED_CSV.parent.mkdir(parents=True, exist_ok=True)
    fieldnames = ["id", "text_masked", "label", "source", "year"]
    with PROCESSED_CSV.open("w", encoding="utf-8", newline="") as handle:
        writer = csv.DictWriter(handle, fieldnames=fieldnames)
        writer.writeheader()
        writer.writerows(cleaned_records)

    # Sınıf bazlı istatistikler
    by_label: dict[str, list[str]] = {"normal": [], "spam": []}
    for rec in cleaned_records:
        by_label[rec["label"]].append(rec["text_masked"])

    def _stats(texts: list[str]) -> dict[str, float | int]:
        lengths = [len(t) for t in texts]
        words = [len(t.split()) for t in texts]
        with_url = sum(1 for t in texts if URL_RE.search(t))
        with_phone = sum(1 for t in texts if "[TELEFON]" in t)
        with_urgency = sum(1 for t in texts if URGENCY_RE.search(t))
        n = len(texts) or 1
        return {
            "count": len(texts),
            "avg_chars": round(sum(lengths) / n, 1),
            "median_chars": int(median(lengths)) if lengths else 0,
            "avg_words": round(sum(words) / n, 1),
            "url_pct": round(100.0 * with_url / n, 1),
            "phone_pct": round(100.0 * with_phone / n, 1),
            "urgency_pct": round(100.0 * with_urgency / n, 1),
        }

    normal_stats = _stats(by_label["normal"])
    spam_stats = _stats(by_label["spam"])

    report_lines = [
        "# 01 — TurkishSMSCollection Keşifsel Veri Analizi (EDA)",
        "",
        "## Genel Özet",
        "",
        f"- **Ham geçerli satır:** {total_raw}",
        f"- **Bozuk / atlanan satır:** {malformed}",
        f"- **Çıkarılan birebir tekrar (duplicate):** {duplicate_count}",
        f"- **Temiz ve maskelenmiş toplam kayıt:** {len(cleaned_records)}",
        "",
        "## Sınıf Dağılımı ve Özellikler",
        "",
        "| Sınıf | Kayıt | Ort. Karakter | Medyan Karakter | Ort. Kelime | "
        "URL İçeren (%) | Telefon İçeren (%) | Aciliyet/Fırsat Dili (%) |",
        "|---|---:|---:|---:|---:|---:|---:|---:|",
        (
            f"| `normal` | {normal_stats['count']} | {normal_stats['avg_chars']} | "
            f"{normal_stats['median_chars']} | {normal_stats['avg_words']} | "
            f"%{normal_stats['url_pct']} | %{normal_stats['phone_pct']} | "
            f"%{normal_stats['urgency_pct']} |"
        ),
        (
            f"| `spam` | {spam_stats['count']} | {spam_stats['avg_chars']} | "
            f"{spam_stats['median_chars']} | {spam_stats['avg_words']} | "
            f"%{spam_stats['url_pct']} | %{spam_stats['phone_pct']} | "
            f"%{spam_stats['urgency_pct']} |"
        ),
        "",
        "## KVKK Maskeleme Özeti",
        "",
        "| Maskelenen Veri Türü | Adet |",
        "|---|---:|",
    ]
    for key, val in sorted(pii_totals.items()):
        report_lines.append(f"| `{key}` | {val} |")

    report_lines.extend(
        [
            "",
            "## Kritik Gözlem (Kavram Kayması / Concept Drift)",
            "",
            "- Bu veri seti **2021** tarihlidir ve ağırlıklı olarak ticari reklam/kampanya "
            "SMS'lerini (`spam`) içerir.",
            "- 2026'daki güncel dolandırıcılık kalıpları (sahte HGS/trafik cezası, "
            "PTT/kargo adres güncelleme, sahte e-Devlet/icra, WhatsApp/ilan dolandırıcılığı) "
            "bu sette neredeyse yoktur.",
            "- Bu nedenle `TurkishSMSCollection` **başlangıç/eğitim** tabanı olarak kullanılacak; "
            "gerçek performans **2026'da toplanan güncel test seti** (zamana göre ayrım) üzerinde "
            "ölçülecektir.",
        ]
    )

    REPORT_MD.parent.mkdir(parents=True, exist_ok=True)
    REPORT_MD.write_text("\n".join(report_lines) + "\n", encoding="utf-8")
    print(f"EDA tamamlandı: {len(cleaned_records)} kayıt -> {PROCESSED_CSV}")
    print(f"Rapor yazıldı: {REPORT_MD}")


if __name__ == "__main__":
    run_eda()
