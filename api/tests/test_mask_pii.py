from ml.mask_pii import is_valid_luhn, is_valid_tckn, mask_pii


def test_masks_turkish_phone_numbers() -> None:
    text = "Detaylar icin 0532 123 45 67 veya +90 (212) 212 90 70 numarasini arayin."
    result = mask_pii(text)
    assert "[TELEFON]" in result.text
    assert "0532" not in result.text
    assert "212 90 70" not in result.text
    assert result.counts["phone"] == 2


def test_masks_iban_and_luhn_valid_card_only() -> None:
    assert is_valid_luhn("4532015112830366") is True
    assert is_valid_luhn("0609006469100018") is False

    text = (
        "Odeme: TR33 0006 1005 1978 6457 8413 26 kart 4532-0151-1283-0366 MERSIS:0609006469100018"
    )
    result = mask_pii(text)
    assert "[IBAN]" in result.text
    assert "[KART_NO]" in result.text
    assert "TR33" not in result.text
    assert "4532" not in result.text
    assert "0609006469100018" in result.text


def test_masks_valid_tckn_only() -> None:
    # 10000000146 geçerli bir TCKN checksum'ına sahiptir; 12345678901 değildir.
    assert is_valid_tckn("10000000146") is True
    assert is_valid_tckn("12345678901") is False

    text = "TCKN: 10000000146 takip no: 12345678901"
    result = mask_pii(text)
    assert "[TCKN]" in result.text
    assert "10000000146" not in result.text
    assert "12345678901" in result.text


def test_preserves_urls_while_masking_email() -> None:
    text = (
        "Kargonuz icin https://ptt-kargo-ornek.xyz/takip/10000000146 adresine girin "
        "veya destek@ornek.com adresine yazin."
    )
    result = mask_pii(text)
    assert "https://ptt-kargo-ornek.xyz/takip/10000000146" in result.text
    assert "[EPOSTA]" in result.text
    assert "destek@ornek.com" not in result.text
