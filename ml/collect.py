"""Güncel (2026+) örnekleri KVKK maskeleyerek veri setine ekleyen CLI aracı.

Kullanım (Google Form veya kendi CSV dosyanızdan içe aktarma):
    python -m ml.collect --input ml/data/raw/form_responses.csv

Beklenen giriş CSV sütunları:
    text, label (normal | promo_spam | scam), channel (opsiyonel, varsayılan: other)
"""

from __future__ import annotations

import argparse
import csv
from pathlib import Path

from ml.mask_pii import mask_pii

ROOT_DIR = Path(__file__).resolve().parent.parent
DEFAULT_OUTPUT = ROOT_DIR / "ml" / "data" / "processed" / "turkish_scam_2026_collected.csv"
VALID_LABELS = {"normal", "promo_spam", "scam"}
VALID_CHANNELS = {"sms", "whatsapp", "instagram", "classifieds", "other"}
FIELDNAMES = ["id", "text_masked", "label", "channel", "source", "year"]


def import_csv(
    input_path: Path,
    output_path: Path = DEFAULT_OUTPUT,
    source: str = "crowdsourced_2026",
    year: str = "2026",
) -> tuple[int, int]:
    """Ham CSV'deki örnekleri maskeler, tekilleştirir ve hedef CSV'ye ekler.

    Returns:
        (eklenen_sayisi, atlanan_sayisi)
    """
    existing_keys: set[tuple[str, str]] = set()
    existing_rows: list[dict[str, str]] = []

    if output_path.exists():
        with output_path.open("r", encoding="utf-8", newline="") as handle:
            for row in csv.DictReader(handle):
                existing_rows.append(row)
                existing_keys.add((row["text_masked"].lower(), row["label"]))

    added = 0
    skipped = 0

    with input_path.open("r", encoding="utf-8-sig", newline="") as handle:
        reader = csv.DictReader(handle)
        for row in reader:
            raw_text = (row.get("text") or "").strip()
            label = (row.get("label") or "").strip().lower()
            channel = (row.get("channel") or "other").strip().lower()

            if len(raw_text) < 3 or label not in VALID_LABELS:
                skipped += 1
                continue
            if channel not in VALID_CHANNELS:
                channel = "other"

            masked_text = mask_pii(raw_text).text
            key = (masked_text.lower(), label)
            if key in existing_keys:
                skipped += 1
                continue

            existing_keys.add(key)
            added += 1
            existing_rows.append(
                {
                    "id": f"col26_{len(existing_rows) + 1:04d}",
                    "text_masked": masked_text,
                    "label": label,
                    "channel": channel,
                    "source": source,
                    "year": year,
                }
            )

    output_path.parent.mkdir(parents=True, exist_ok=True)
    with output_path.open("w", encoding="utf-8", newline="") as handle:
        writer = csv.DictWriter(handle, fieldnames=FIELDNAMES)
        writer.writeheader()
        writer.writerows(existing_rows)

    return added, skipped


def main() -> None:
    parser = argparse.ArgumentParser(description="Güncel örnekleri KVKK maskeleyerek içe aktar.")
    parser.add_argument("--input", type=Path, required=True, help="Ham giriş CSV yolu")
    parser.add_argument("--output", type=Path, default=DEFAULT_OUTPUT, help="Hedef CSV yolu")
    parser.add_argument("--source", default="crowdsourced_2026", help="Veri kaynağı etiketi")
    parser.add_argument("--year", default="2026", help="Yıl bilgisi")
    args = parser.parse_args()

    added, skipped = import_csv(args.input, args.output, source=args.source, year=args.year)
    print(f"Tamamlandı: {added} kayıt eklendi, {skipped} kayıt atlandı -> {args.output}")


if __name__ == "__main__":
    main()
