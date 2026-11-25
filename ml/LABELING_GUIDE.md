# Etiketleme Rehberi (Taxonomy)

SahteMi veri setinde mesajlar 3 ana sınıfa ayrılır:

| Etiket | Tanım | Örnek |
|---|---|---|
| `normal` | Kişisel yazışma, gerçek banka/kargo/kurum bilgilendirmesi (doğrulanmış alan adı veya işlem bildirimi) | *"Akşam 7'de buluşalım mı?"*, *"Kargonuz teslim edilmiştir."* |
| `promo_spam` | İstenmeyen ama dolandırıcılık amacı taşımayan reklam, bahis dışı kampanya, pazarlama SMS'i | *"Digiturk'ten size özel ilk ay 10 TL fırsat..."* |
| `scam` | Kimlik avı (phishing/smishing), sahte kurum/banka/kargo linki, sahte icra/ceza korkutması, sahte iş/yatırım veya ilan dolandırıcılığı | *"HGS borcunuz için son gün, icra başlamadan ödeyin: https://..."* |

## Veri Toplama Kuralları (KVKK)

1. Çevreden toplanan her örnek **açık rıza** ile alınır.
2. Ham metinler repoya **asla** eklenmez (`ml/data/raw/` `.gitignore` içindedir).
3. Kaydetmeden önce tüm metinler `ml.mask_pii.mask_pii()` fonksiyonundan geçirilir (`[TELEFON]`, `[IBAN]`, `[TCKN]`, `[KART_NO]`, `[EPOSTA]`).
4. Şüpheli URL'ler analiz sinyali olduğu için **korunur**.
5. Sentetik (LLM ile üretilmiş) örnekler yalnızca eğitim verisini dengelemek için kullanılabilir; **test/eval setinde asla yer almaz**.
