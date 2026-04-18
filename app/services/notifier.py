import logging
import httpx
from app.core.config import settings

logger = logging.getLogger(__name__)


async def send_alert(rule, device, diff_text: str) -> None:
    if rule.channel == "telegram":
        await _send_telegram(rule.target, device, diff_text)
    elif rule.channel == "email":
        await _send_email(rule.target, device, diff_text)
    else:
        logger.warning(f"Unknown alert channel: {rule.channel}")


async def _send_telegram(chat_id: str, device, diff_text: str) -> None:
    if not settings.TELEGRAM_BOT_TOKEN:
        logger.warning("TELEGRAM_BOT_TOKEN not set, skipping")
        return

    diff_preview = diff_text[:800] + "..." if len(diff_text) > 800 else diff_text
    message = (
        f"⚠️ *Config change detected*\n\n"
        f"*Device:* `{device.hostname}` ({device.ip_address})\n"
        f"*Vendor:* {device.vendor or 'unknown'}\n\n"
        f"```diff\n{diff_preview}\n```"
    )

    url = f"https://api.telegram.org/bot{settings.TELEGRAM_BOT_TOKEN}/sendMessage"
    payload = {
        "chat_id": chat_id,
        "text": message,
        "parse_mode": "Markdown",
    }

    try:
        async with httpx.AsyncClient(timeout=10) as client:
            resp = await client.post(url, json=payload)
            resp.raise_for_status()
        logger.info(f"Telegram alert sent to {chat_id} for device {device.hostname}")
    except Exception as e:
        logger.error(f"Failed to send Telegram alert: {e}")


async def _send_email(to_email: str, device, diff_text: str) -> None:
    if not settings.SMTP_HOST:
        logger.warning("SMTP not configured, skipping email alert")
        return

    import smtplib
    from email.mime.text import MIMEText
    from email.mime.multipart import MIMEMultipart

    subject = f"[NCM] Config change on {device.hostname}"
    body = (
        f"Configuration change detected on device:\n\n"
        f"Hostname : {device.hostname}\n"
        f"IP       : {device.ip_address}\n"
        f"Vendor   : {device.vendor or 'unknown'}\n\n"
        f"--- Diff ---\n{diff_text}"
    )

    msg = MIMEMultipart()
    msg["From"] = settings.SMTP_USER
    msg["To"] = to_email
    msg["Subject"] = subject
    msg.attach(MIMEText(body, "plain"))

    try:
        with smtplib.SMTP(settings.SMTP_HOST, settings.SMTP_PORT) as server:
            server.starttls()
            server.login(settings.SMTP_USER, settings.SMTP_PASSWORD)
            server.sendmail(settings.SMTP_USER, to_email, msg.as_string())
        logger.info(f"Email alert sent to {to_email} for device {device.hostname}")
    except Exception as e:
        logger.error(f"Failed to send email alert: {e}")
