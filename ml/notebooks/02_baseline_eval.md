# 02 — Baseline Model Değerlendirme (TF-IDF + Lojistik Regresyon)

## Karşılaştırma: Rastgele Ayrım (2021) vs. Zamana Göre Ayrım (2026)

| Senaryo | Örnek | Doğruluk | Kesinlik (Precision) | Duyarlılık (Recall) | F1 | Yanlış Alarm (FPR) |
|---|---:|---:|---:|---:|---:|---:|
| Rastgele ayrım (2021 -> 2021) | 947 | %98.8 | %99.4 | %98.4 | **%98.9** | %0.7 |
| Zamana göre ayrım (2021 -> 2026) | 50 | %82.0 | %83.3 | %80.0 | **%81.6** | %16.0 |

## Kavram Kayması (Concept Drift) Özeti

- **F1 düşüşü:** +17.3 puan
- **Duyarlılık (Recall) düşüşü:** +18.4 puan (2026 dolandırıcılıklarından 5/25 tanesi kaçırıldı)
- **Yanlış alarm (FP):** 4/25 normal 2026 mesajı yanlışlıkla riskli işaretlendi

## Hata Analizi (2026 Test Seti)

### Kaçırılan Dolandırıcılıklar (False Negatives — 5 adet)

- `p=0.22` | `whatsapp` | Kuzeninim ben, acil hastaneye gitmem gerekti kartim limit dolu. 3.500 TL atabilir misin yarin oglen gonderirim.
- `p=0.29` | `classifieds` | Merhaba, urununuzu begendim ama kurye ile aldiracagim. Kurye odeme linkini gonderiyorum, kartinizi girip parayi alabilirsiniz: https://yurtici-kurye-tahsilat.net
- `p=0.39` | `whatsapp` | Selam, ben finans danismaniyim. Borsa ve kripto yapay zeka botumuzla aylik %40 garantili getiri sagliyoruz. Gruba katil: https://yatirim-vip-sinyal.xyz
- `p=0.42` | `sms` | MNG Kargo: Paketiniz subede bekliyor, adres dogrulamasi yapilmazsa iade olacak: https://mng-adres-dogrula.click
- `p=0.44` | `whatsapp` | Anne telefonum bozuldu yeni numaram bu, acil 7.500 TL gondermen lazim aksam geri atacagim. IBAN: [IBAN]

### Yanlış Alarmlar (False Positives — 4 adet)

- `p=0.81` | `sms` | Garanti BBVA: Hesabiniza 2.500,00 TL FAST transferi gerceklesmistir.
- `p=0.75` | `sms` | Ziraat Bankasi: 1234 ile biten kartinizla 320,50 TL tutarinda harcama yapilmistir.
- `p=0.72` | `sms` | Akbank 3D Secure: 1.240,00 TL tutarindaki alisverisiniz icin tek kullanimlik sifreniz 649201. Bu sifreyi kimseyle paylasmayiniz.
- `p=0.70` | `sms` | ISKI Bilgilendirme: Abone numaraniza ait Kasim 2026 donemi su faturaniz 245,00 TL olarak olusturulmustur. Son odeme tarihi 05.12.2026.
