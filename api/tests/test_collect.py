from pathlib import Path

from ml.collect import import_csv


def test_import_csv_masks_pii_and_deduplicates(tmp_path: Path) -> None:
    raw_csv = tmp_path / "raw.csv"
    raw_csv.write_text(
        "text,label,channel\n"
        '"Acil 0532 111 22 33 ara TR33 0006 1005 1978 6457 8413 26",scam,whatsapp\n'
        '"Acil 0532 111 22 33 ara TR33 0006 1005 1978 6457 8413 26",scam,whatsapp\n'
        '"Gecersiz etiket ornegi",bilinmiyor,sms\n'
        '"Aksam gorusuruz",normal,unknown_channel\n',
        encoding="utf-8",
    )
    out_csv = tmp_path / "out.csv"

    added, skipped = import_csv(raw_csv, out_csv)
    assert added == 2
    assert skipped == 2

    content = out_csv.read_text(encoding="utf-8")
    assert "[TELEFON]" in content
    assert "[IBAN]" in content
    assert "0532" not in content
    assert "TR33" not in content
    assert ",other," in content
