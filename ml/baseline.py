"""Baseline model (TF-IDF + Lojistik Regresyon) eğitimi ve zamansal değerlendirme.

İki değerlendirme karşılaştırılır:
1. Rastgele ayrım (2021 -> 2021): Akademik çalışmalarda sık raporlanan senaryo.
2. Zamana göre ayrım (2021 -> 2026): Eski veriyle eğitilip güncel 2026
   dolandırıcılık ve normal mesajları üzerinde kavram kayması (concept drift) ölçümü.

Kullanım:
    python -m ml.baseline
"""

from __future__ import annotations

import csv
from dataclasses import dataclass
from pathlib import Path

import joblib
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.linear_model import LogisticRegression
from sklearn.metrics import (
    accuracy_score,
    confusion_matrix,
    f1_score,
    precision_score,
    recall_score,
)
from sklearn.model_selection import train_test_split
from sklearn.pipeline import Pipeline

ROOT_DIR = Path(__file__).resolve().parent.parent
DATA_2021 = ROOT_DIR / "ml" / "data" / "processed" / "turkish_sms_clean.csv"
DATA_2026_SEED = ROOT_DIR / "ml" / "data" / "processed" / "turkish_scam_2026_seed.csv"
DATA_2026_COLLECTED = ROOT_DIR / "ml" / "data" / "processed" / "turkish_scam_2026_collected.csv"
MODEL_OUT = ROOT_DIR / "ml" / "models" / "baseline_tfidf_lr.joblib"
REPORT_OUT = ROOT_DIR / "ml" / "notebooks" / "02_baseline_eval.md"


@dataclass
class EvalMetrics:
    n_samples: int
    accuracy: float
    precision: float
    recall: float
    f1: float
    fpr: float
    tn: int
    fp: int
    fn: int
    tp: int


def build_pipeline() -> Pipeline:
    return Pipeline(
        [
            (
                "tfidf",
                TfidfVectorizer(
                    ngram_range=(1, 2),
                    sublinear_tf=True,
                    min_df=2,
                    max_features=15000,
                ),
            ),
            (
                "clf",
                LogisticRegression(
                    max_iter=1000,
                    class_weight="balanced",
                    random_state=42,
                ),
            ),
        ]
    )


def load_binary_dataset(paths: list[Path]) -> tuple[list[str], list[int], list[dict[str, str]]]:
    """Veri dosyalarını okur: spam/scam -> 1, normal -> 0."""
    texts: list[str] = []
    labels: list[int] = []
    meta: list[dict[str, str]] = []

    for path in paths:
        if not path.exists():
            continue
        with path.open("r", encoding="utf-8", newline="") as handle:
            for row in csv.DictReader(handle):
                label_str = row["label"].strip().lower()
                if label_str in {"spam", "scam"}:
                    y = 1
                elif label_str == "normal":
                    y = 0
                else:
                    continue
                texts.append(row["text_masked"])
                labels.append(y)
                meta.append(row)
    return texts, labels, meta


def compute_metrics(y_true: list[int], y_pred: list[int]) -> EvalMetrics:
    tn, fp, fn, tp = confusion_matrix(y_true, y_pred, labels=[0, 1]).ravel()
    fpr = fp / (fp + tn) if (fp + tn) else 0.0
    return EvalMetrics(
        n_samples=len(y_true),
        accuracy=round(float(accuracy_score(y_true, y_pred)), 4),
        precision=round(float(precision_score(y_true, y_pred, zero_division=0)), 4),
        recall=round(float(recall_score(y_true, y_pred, zero_division=0)), 4),
        f1=round(float(f1_score(y_true, y_pred, zero_division=0)), 4),
        fpr=round(float(fpr), 4),
        tn=int(tn),
        fp=int(fp),
        fn=int(fn),
        tp=int(tp),
    )


def pct(val: float) -> str:
    return f"%{val * 100:.1f}"


def run_baseline() -> None:
    x_2021, y_2021, _ = load_binary_dataset([DATA_2021])
    x_2026, y_2026, meta_2026 = load_binary_dataset([DATA_2026_SEED, DATA_2026_COLLECTED])

    # 1) Rastgele ayrım (2021 -> 2021)
    x_train, x_val, y_train, y_val = train_test_split(
        x_2021, y_2021, test_size=0.2, stratify=y_2021, random_state=42
    )
    split_model = build_pipeline()
    split_model.fit(x_train, y_train)
    val_preds = split_model.predict(x_val).tolist()
    random_metrics = compute_metrics(y_val, val_preds)

    # 2) Zamana göre ayrım (tüm 2021 ile eğit -> 2026 üzerinde test et)
    full_model = build_pipeline()
    full_model.fit(x_2021, y_2021)
    drift_preds = full_model.predict(x_2026).tolist()
    drift_probs = full_model.predict_proba(x_2026)[:, 1].tolist()
    temporal_metrics = compute_metrics(y_2026, drift_preds)

    # Modeli kaydet
    MODEL_OUT.parent.mkdir(parents=True, exist_ok=True)
    joblib.dump(full_model, MODEL_OUT)

    # 2026 hata analizi
    missed_scams: list[tuple[float, dict[str, str]]] = []
    false_alarms: list[tuple[float, dict[str, str]]] = []
    for y_t, y_p, prob, row in zip(y_2026, drift_preds, drift_probs, meta_2026, strict=True):
        if y_t == 1 and y_p == 0:
            missed_scams.append((prob, row))
        elif y_t == 0 and y_p == 1:
            false_alarms.append((prob, row))

    f1_drop = (random_metrics.f1 - temporal_metrics.f1) * 100
    recall_drop = (random_metrics.recall - temporal_metrics.recall) * 100

    total_pos_2026 = temporal_metrics.tp + temporal_metrics.fn
    total_neg_2026 = temporal_metrics.tn + temporal_metrics.fp

    lines = [
        "# 02 — Baseline Model Değerlendirme (TF-IDF + Lojistik Regresyon)",
        "",
        "## Karşılaştırma: Rastgele Ayrım (2021) vs. Zamana Göre Ayrım (2026)",
        "",
        "| Senaryo | Örnek | Doğruluk | Kesinlik (Precision) | "
        "Duyarlılık (Recall) | F1 | Yanlış Alarm (FPR) |",
        "|---|---:|---:|---:|---:|---:|---:|",
        (
            f"| Rastgele ayrım (2021 -> 2021) | {random_metrics.n_samples} | "
            f"{pct(random_metrics.accuracy)} | {pct(random_metrics.precision)} | "
            f"{pct(random_metrics.recall)} | **{pct(random_metrics.f1)}** | "
            f"{pct(random_metrics.fpr)} |"
        ),
        (
            f"| Zamana göre ayrım (2021 -> 2026) | {temporal_metrics.n_samples} | "
            f"{pct(temporal_metrics.accuracy)} | {pct(temporal_metrics.precision)} | "
            f"{pct(temporal_metrics.recall)} | **{pct(temporal_metrics.f1)}** | "
            f"{pct(temporal_metrics.fpr)} |"
        ),
        "",
        "## Kavram Kayması (Concept Drift) Özeti",
        "",
        f"- **F1 düşüşü:** {f1_drop:+.1f} puan",
        f"- **Duyarlılık (Recall) düşüşü:** {recall_drop:+.1f} puan "
        f"(2026 dolandırıcılıklarından {temporal_metrics.fn}/{total_pos_2026} tanesi kaçırıldı)",
        f"- **Yanlış alarm (FP):** {temporal_metrics.fp}/{total_neg_2026} "
        "normal 2026 mesajı yanlışlıkla riskli işaretlendi",
        "",
        "## Hata Analizi (2026 Test Seti)",
        "",
        f"### Kaçırılan Dolandırıcılıklar (False Negatives — {len(missed_scams)} adet)",
        "",
    ]

    if missed_scams:
        for prob, row in sorted(missed_scams, key=lambda item: item[0]):
            lines.append(
                f"- `p={prob:.2f}` | `{row.get('channel', 'other')}` | {row['text_masked']}"
            )
    else:
        lines.append("- Yok.")

    lines.extend(
        [
            "",
            f"### Yanlış Alarmlar (False Positives — {len(false_alarms)} adet)",
            "",
        ]
    )

    if false_alarms:
        for prob, row in sorted(false_alarms, key=lambda item: item[0], reverse=True):
            lines.append(
                f"- `p={prob:.2f}` | `{row.get('channel', 'other')}` | {row['text_masked']}"
            )
    else:
        lines.append("- Yok.")

    REPORT_OUT.parent.mkdir(parents=True, exist_ok=True)
    REPORT_OUT.write_text("\n".join(lines) + "\n", encoding="utf-8")

    print(
        f"Rastgele ayrım (2021): F1={pct(random_metrics.f1)} "
        f"Recall={pct(random_metrics.recall)} FPR={pct(random_metrics.fpr)}"
    )
    print(
        f"Zamana göre ayrım (2026): F1={pct(temporal_metrics.f1)} "
        f"Recall={pct(temporal_metrics.recall)} FPR={pct(temporal_metrics.fpr)}"
    )
    print(f"Model: {MODEL_OUT}")
    print(f"Rapor: {REPORT_OUT}")


if __name__ == "__main__":
    run_baseline()
