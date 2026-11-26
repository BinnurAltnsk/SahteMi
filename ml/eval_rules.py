"""Kural + Alan Adı motorunu 2026 kıyaslama seti üzerinde değerlendirir.

Kullanım:
    python -m ml.eval_rules
"""

from __future__ import annotations

import csv
from pathlib import Path

from api.schemas.analyze import Channel, RiskLevel
from api.tools.rules import analyze_with_rules

ROOT_DIR = Path(__file__).resolve().parent.parent
DATA_2026_SEED = ROOT_DIR / "ml" / "data" / "processed" / "turkish_scam_2026_seed.csv"
DATA_2026_COLLECTED = ROOT_DIR / "ml" / "data" / "processed" / "turkish_scam_2026_collected.csv"
REPORT_OUT = ROOT_DIR / "ml" / "notebooks" / "03_rules_eval.md"


def run_eval() -> None:
    rows: list[dict[str, str]] = []
    for path in (DATA_2026_SEED, DATA_2026_COLLECTED):
        if not path.exists():
            continue
        with path.open("r", encoding="utf-8", newline="") as handle:
            for row in csv.DictReader(handle):
                if row["label"].strip().lower() in {"scam", "normal"}:
                    rows.append(row)

    tp = fp = tn = fn = 0
    missed: list[tuple[float, dict[str, str]]] = []
    false_alarms: list[tuple[float, dict[str, str]]] = []

    for row in rows:
        y_true = 1 if row["label"].strip().lower() == "scam" else 0
        raw_ch = (row.get("channel") or "other").strip().lower()
        channel = Channel(raw_ch) if raw_ch in {c.value for c in Channel} else Channel.OTHER

        res = analyze_with_rules(row["text_masked"], channel=channel)
        y_pred = 1 if res.risk_level in {RiskLevel.SUSPICIOUS, RiskLevel.SCAM} else 0

        if y_true == 1 and y_pred == 1:
            tp += 1
        elif y_true == 0 and y_pred == 1:
            fp += 1
            false_alarms.append((res.risk_score, row))
        elif y_true == 0 and y_pred == 0:
            tn += 1
        else:
            fn += 1
            missed.append((res.risk_score, row))

    n = len(rows) or 1
    acc = (tp + tn) / n
    prec = tp / (tp + fp) if (tp + fp) else 0.0
    rec = tp / (tp + fn) if (tp + fn) else 0.0
    f1 = 2 * prec * rec / (prec + rec) if (prec + rec) else 0.0
    fpr = fp / (fp + tn) if (fp + tn) else 0.0

    def pct(v: float) -> str:
        return f"%{v * 100:.1f}"

    lines = [
        "# 03 — Kural + Alan Adı Motoru Değerlendirme (2026 Test Seti)",
        "",
        "| Model | Örnek | Doğruluk | Kesinlik | Duyarlılık | F1 | Yanlış Alarm (FPR) |",
        "|---|---:|---:|---:|---:|---:|---:|",
        f"| Kural + Alan Adı Motoru (2026) | {len(rows)} | {pct(acc)} | {pct(prec)} | "
        f"{pct(rec)} | **{pct(f1)}** | **{pct(fpr)}** |",
        "",
        f"- **TP:** {tp} · **FP:** {fp} · **TN:** {tn} · **FN:** {fn}",
        "",
        f"## Kaçırılan Dolandırıcılıklar ({len(missed)} adet)",
        "",
    ]
    if missed:
        for score, row in missed:
            lines.append(f"- `score={score:.2f}` | `{row.get('channel')}` | {row['text_masked']}")
    else:
        lines.append("- Yok.")

    lines.extend(["", f"## Yanlış Alarmlar ({len(false_alarms)} adet)", ""])
    if false_alarms:
        for score, row in false_alarms:
            lines.append(f"- `score={score:.2f}` | `{row.get('channel')}` | {row['text_masked']}")
    else:
        lines.append("- Yok.")

    REPORT_OUT.parent.mkdir(parents=True, exist_ok=True)
    REPORT_OUT.write_text("\n".join(lines) + "\n", encoding="utf-8")
    print(
        f"Kural+Alan Adı (2026): F1={pct(f1)} Recall={pct(rec)} "
        f"FPR={pct(fpr)} (TP={tp} FP={fp} FN={fn})"
    )


if __name__ == "__main__":
    run_eval()
