# 01 — TurkishSMSCollection Keşifsel Veri Analizi (EDA)

## Genel Özet

- **Ham geçerli satır:** 4751
- **Bozuk / atlanan satır:** 0
- **Çıkarılan birebir tekrar (duplicate):** 18
- **Temiz ve maskelenmiş toplam kayıt:** 4733

## Sınıf Dağılımı ve Özellikler

| Sınıf | Kayıt | Ort. Karakter | Medyan Karakter | Ort. Kelime | URL İçeren (%) | Telefon İçeren (%) | Aciliyet/Fırsat Dili (%) |
|---|---:|---:|---:|---:|---:|---:|---:|
| `normal` | 2212 | 46.4 | 37 | 7.2 | %0.0 | %0.0 | %1.1 |
| `spam` | 2521 | 175.7 | 159 | 22.6 | %34.7 | %13.4 | %45.5 |

## KVKK Maskeleme Özeti

| Maskelenen Veri Türü | Adet |
|---|---:|
| `card` | 1 |
| `email` | 6 |
| `phone` | 384 |

## Kritik Gözlem (Kavram Kayması / Concept Drift)

- Bu veri seti **2021** tarihlidir ve ağırlıklı olarak ticari reklam/kampanya SMS'lerini (`spam`) içerir.
- 2026'daki güncel dolandırıcılık kalıpları (sahte HGS/trafik cezası, PTT/kargo adres güncelleme, sahte e-Devlet/icra, WhatsApp/ilan dolandırıcılığı) bu sette neredeyse yoktur.
- Bu nedenle `TurkishSMSCollection` **başlangıç/eğitim** tabanı olarak kullanılacak; gerçek performans **2026'da toplanan güncel test seti** (zamana göre ayrım) üzerinde ölçülecektir.
