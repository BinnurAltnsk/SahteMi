# SahteMi Telegram Botu

Kullanıcıların SMS, WhatsApp, Instagram DM veya ilan sitelerinden gelen şüpheli mesaj ve bağlantıları iletip gerekçeli risk sonucu aldığı Telegram botudur.

## Özellikler

- Doğrudan yapıştırılan veya iletilen (forwarded) mesajları ve medya açıklamalarını (caption) analiz eder.
- Kanal belirterek analiz desteği: `/sms`, `/whatsapp`, `/instagram`, `/ilan`.
- Tehdit istihbaratı veritabanı özeti: `/istatistik` (veya `/stats`).
- Şüpheli bağlantıları `<code>` bloğu içinde ve web önizlemesi kapalı (`disable_web_page_preview=True`) döndürerek yanlışlıkla tıklanmasını engeller.

## Kurulum ve Çalıştırma

### 1. Bot Token Alma
Telegram'da [@BotFather](https://t.me/BotFather) üzerinden `/newbot` komutuyla bot oluşturup token alın ve `.env` dosyanıza ekleyin:

```env
TELEGRAM_BOT_TOKEN=123456:ABC-DEF...
API_BASE_URL=http://localhost:8000
```

### 2. Yerel Çalıştırma

FastAPI servisi ayaktayken:

```bash
python -m bot.main
```

### 3. Docker Compose ile Çalıştırma

`bot` servisi `bot` profiliyle tanımlıdır (token tanımlı değilken `docker compose up` akışını bozmamak için):

```bash
docker compose --profile bot up --build -d
```
