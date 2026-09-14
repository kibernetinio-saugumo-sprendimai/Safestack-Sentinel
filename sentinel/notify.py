import json
import os
from urllib.request import Request, urlopen

def telegram(report: dict, timeout: float = 8.0) -> bool:
    token, chat = os.getenv("SENTINEL_TELEGRAM_BOT_TOKEN"), os.getenv("SENTINEL_TELEGRAM_CHAT_ID")
    if not token or not chat:
        return False
    text = f"SafeStack Sentinel: score {report['score']}\n{report['generated_at']}"
    data = json.dumps({"chat_id": chat, "text": text}).encode()
    req = Request(f"https://api.telegram.org/bot{token}/sendMessage", data=data,
                  headers={"Content-Type": "application/json"}, method="POST")
    with urlopen(req, timeout=timeout) as response:
        return 200 <= response.status < 300
