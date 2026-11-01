"""Explicit opt-in notifications to a fixed HTTPS endpoint without redirects."""
import json
import os
import re
from http.client import HTTPSConnection


def telegram(report: dict, timeout: float = 8.0) -> bool:
    token = os.getenv("SENTINEL_TELEGRAM_BOT_TOKEN")
    chat = os.getenv("SENTINEL_TELEGRAM_CHAT_ID")
    if not token or not chat:
        return False
    if not re.fullmatch(r"[0-9]+:[A-Za-z0-9_-]+", token):
        raise ValueError("Invalid Telegram bot token format")
    text = f"SafeStack Sentinel: score {report['score']}\n{report['generated_at']}"
    data = json.dumps({"chat_id": chat, "text": text}).encode("utf-8")
    connection = HTTPSConnection("api.telegram.org", timeout=timeout)
    try:
        connection.request("POST", f"/bot{token}/sendMessage", body=data,
                           headers={"Content-Type": "application/json"})
        response = connection.getresponse()
        return 200 <= response.status < 300
    finally:
        connection.close()
