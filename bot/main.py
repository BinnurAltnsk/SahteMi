"""SahteMi Telegram botu giriş noktası.

Kullanım:
    python -m bot.main
"""

from __future__ import annotations

import logging
import sys

from telegram.ext import Application, CommandHandler, MessageHandler, filters

from api.core.logging import setup_logging
from bot.client import SahteMiApiClient
from bot.config import BotSettings, get_bot_settings
from bot.handlers import (
    analyze_message_handler,
    help_command,
    start_command,
    stats_command,
)

logger = logging.getLogger(__name__)


def build_application(settings: BotSettings) -> Application:
    """Telegram bot uygulamasını ve tüm işleyicileri yapılandırır."""
    if not settings.telegram_bot_token.strip():
        raise ValueError(
            "TELEGRAM_BOT_TOKEN tanımlı değil. .env dosyanıza BotFather token'ını ekleyin."
        )

    application = Application.builder().token(settings.telegram_bot_token.strip()).build()
    application.bot_data["api_client"] = SahteMiApiClient(
        base_url=settings.api_base_url,
        timeout=settings.api_timeout_seconds,
    )

    application.add_handler(CommandHandler("start", start_command))
    application.add_handler(CommandHandler(["help", "yardim"], help_command))
    application.add_handler(CommandHandler(["stats", "istatistik"], stats_command))
    application.add_handler(
        CommandHandler(["sms", "whatsapp", "instagram", "ilan"], analyze_message_handler)
    )
    application.add_handler(
        MessageHandler(
            (filters.TEXT & ~filters.COMMAND) | filters.CAPTION,
            analyze_message_handler,
        )
    )
    return application


def main() -> None:
    settings = get_bot_settings()
    setup_logging(settings.log_level)

    try:
        app = build_application(settings)
    except ValueError as exc:
        logger.error("%s", exc)
        sys.exit(1)

    logger.info("SahteMi Telegram botu başlatılıyor (API: %s)", settings.api_base_url)
    app.run_polling(drop_pending_updates=True)


if __name__ == "__main__":
    main()
