"""Telegram komut ve mesaj işleyicileri."""

from __future__ import annotations

import logging

from telegram import Update
from telegram.constants import ChatAction, ParseMode
from telegram.ext import ContextTypes

from api.schemas.analyze import Channel
from bot.client import ApiClientError, SahteMiApiClient
from bot.formatter import (
    format_analysis_result,
    format_help_message,
    format_stats_message,
    format_welcome_message,
)

logger = logging.getLogger(__name__)

MIN_TEXT_LENGTH = 3
MAX_TEXT_LENGTH = 4000

_COMMAND_CHANNEL_MAP: dict[str, Channel] = {
    "sms": Channel.SMS,
    "whatsapp": Channel.WHATSAPP,
    "instagram": Channel.INSTAGRAM,
    "ilan": Channel.CLASSIFIEDS,
}


def extract_channel_and_text(raw_text: str) -> tuple[Channel, str]:
    """İsteğe bağlı kanal komutunu (/sms, /whatsapp vb.) metinden ayırır."""
    stripped = raw_text.strip()
    if not stripped.startswith("/"):
        return Channel.OTHER, stripped

    parts = stripped.split(maxsplit=1)
    command_token = parts[0].lstrip("/").split("@", maxsplit=1)[0].lower()
    if command_token in _COMMAND_CHANNEL_MAP:
        body = parts[1].strip() if len(parts) > 1 else ""
        return _COMMAND_CHANNEL_MAP[command_token], body

    return Channel.OTHER, stripped


def _get_api_client(context: ContextTypes.DEFAULT_TYPE) -> SahteMiApiClient:
    client = context.application.bot_data.get("api_client")
    if isinstance(client, SahteMiApiClient):
        return client
    return SahteMiApiClient()


async def start_command(update: Update, _context: ContextTypes.DEFAULT_TYPE) -> None:
    if update.message is None:
        return
    await update.message.reply_text(
        format_welcome_message(),
        parse_mode=ParseMode.HTML,
        disable_web_page_preview=True,
    )


async def help_command(update: Update, _context: ContextTypes.DEFAULT_TYPE) -> None:
    if update.message is None:
        return
    await update.message.reply_text(
        format_help_message(),
        parse_mode=ParseMode.HTML,
        disable_web_page_preview=True,
    )


async def stats_command(update: Update, context: ContextTypes.DEFAULT_TYPE) -> None:
    if update.message is None:
        return
    api_client = _get_api_client(context)
    try:
        stats = await api_client.get_threat_stats()
        reply = format_stats_message(stats)
    except ApiClientError as exc:
        logger.warning("Tehdit istatistikleri alınamadı: %s", exc)
        reply = f"⚠️ {exc}"

    await update.message.reply_text(
        reply,
        parse_mode=ParseMode.HTML,
        disable_web_page_preview=True,
    )


async def analyze_message_handler(update: Update, context: ContextTypes.DEFAULT_TYPE) -> None:
    """Düz metin, iletilen mesaj, medya açıklaması veya kanal komutlarını analiz eder."""
    message = update.message
    if message is None:
        return

    raw_text = message.text or message.caption or ""
    channel, text = extract_channel_and_text(raw_text)

    if len(text) < MIN_TEXT_LENGTH:
        await message.reply_text(
            "Analiz için en az 3 karakterlik bir mesaj veya bağlantı göndermelisiniz.",
            disable_web_page_preview=True,
        )
        return

    truncated = False
    if len(text) > MAX_TEXT_LENGTH:
        text = text[:MAX_TEXT_LENGTH]
        truncated = True

    if update.effective_chat is not None:
        await context.bot.send_chat_action(
            chat_id=update.effective_chat.id,
            action=ChatAction.TYPING,
        )

    api_client = _get_api_client(context)
    try:
        result = await api_client.analyze(text, channel=channel)
        reply = format_analysis_result(result)
        if truncated:
            reply += "\n\n<i>Not: Mesaj çok uzun olduğu için ilk 4000 karakter analiz edildi.</i>"
    except ApiClientError as exc:
        logger.warning("Mesaj analizi başarısız: %s", exc)
        reply = f"⚠️ Analiz şu anda yapılamadı: {exc}"

    await message.reply_text(
        reply,
        parse_mode=ParseMode.HTML,
        disable_web_page_preview=True,
    )
