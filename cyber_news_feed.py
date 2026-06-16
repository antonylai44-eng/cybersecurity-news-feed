#!/usr/bin/env python3
import argparse
import datetime as dt
import html
import json
import os
import re
import sys
import time
from dataclasses import dataclass
from email.utils import parsedate_to_datetime
from pathlib import Path
from typing import Iterable, Optional
from urllib.parse import urlparse

import feedparser
import requests
from bs4 import BeautifulSoup, MarkupResemblesLocatorWarning
from deep_translator import GoogleTranslator
from dotenv import load_dotenv
from zoneinfo import ZoneInfo
import warnings


warnings.filterwarnings("ignore", category=MarkupResemblesLocatorWarning)


DEFAULT_SOURCES = [
    {
        "name": "HKCERT Security Bulletin",
        "url": "https://www.hkcert.org/rss/security-bulletin",
        "weight": 10,
    },
    {
        "name": "GovCERT.HK Alerts",
        "url": "https://www.govcert.gov.hk/en/alerts.php",
        "kind": "govcert_hk",
        "weight": 10,
    },
    {
        "name": "CISA Cybersecurity Advisories",
        "url": "https://www.cisa.gov/cybersecurity-advisories/all.xml",
        "weight": 8,
    },
    {
        "name": "The Hacker News",
        "url": "https://feeds.feedburner.com/TheHackersNews",
        "weight": 7,
    },
    {
        "name": "BleepingComputer",
        "url": "https://www.bleepingcomputer.com/feed/",
        "weight": 7,
    },
    {
        "name": "SecurityWeek",
        "url": "https://www.securityweek.com/feed/",
        "weight": 7,
    },
    {
        "name": "The Record",
        "url": "https://therecord.media/feed/",
        "weight": 6,
    },
    {
        "name": "Microsoft Security Response Center",
        "url": "https://api.msrc.microsoft.com/update-guide/rss",
        "weight": 8,
    },
]

AI_SOURCES = [
    {
        "name": "OpenAI News",
        "url": "https://openai.com/news/rss.xml",
        "weight": 9,
    },
    {
        "name": "Google AI Blog",
        "url": "https://blog.google/technology/ai/rss/",
        "weight": 8,
    },
    {
        "name": "MarkTechPost",
        "url": "https://www.marktechpost.com/feed/",
        "weight": 7,
    },
    {
        "name": "AI News",
        "url": "https://www.artificialintelligence-news.com/feed/",
        "weight": 7,
    },
    {
        "name": "Hugging Face Blog",
        "url": "https://huggingface.co/blog/feed.xml",
        "weight": 8,
    },
    {
        "name": "MIT News AI",
        "url": "https://news.mit.edu/rss/topic/artificial-intelligence2",
        "weight": 6,
    },
]

REGIONAL_KEYWORDS = [
    "hong kong",
    "hkcert",
    "govcert.hk",
    "hksar",
    "china",
    "chinese",
    "beijing",
    "shanghai",
    "guangdong",
    "macau",
    "taiwan",
    "asia",
    "apac",
]

CRITICAL_KEYWORDS = [
    "zero-day",
    "zero day",
    "exploited",
    "actively exploited",
    "ransomware",
    "critical",
    "remote code execution",
    "rce",
    "supply chain",
    "data breach",
    "breach",
    "leak",
    "backdoor",
    "espionage",
    "apt",
    "vpn",
    "firewall",
    "edge device",
    "chrome",
    "windows",
    "exchange",
    "sharepoint",
    "ivanti",
    "fortinet",
    "palo alto",
    "cisco",
    "citrix",
    "oracle",
    "vmware",
    "veeam",
]

AI_PRIORITY_KEYWORDS = [
    "openai",
    "anthropic",
    "google",
    "gemini",
    "chatgpt",
    "gpt-",
    "llm",
    "large language model",
    "multimodal",
    "reasoning",
    "agent",
    "agents",
    "benchmark",
    "inference",
    "training",
    "fine-tuning",
    "robotics",
    "model release",
    "safety",
    "alignment",
]


@dataclass(frozen=True)
class NewsItem:
    title: str
    summary: str
    link: str
    source: str
    published: dt.datetime
    score: int


def normalized_title(title: str) -> str:
    return re.sub(r"[^a-z0-9]+", " ", title.lower()).strip()


def clean_text(value: str, limit: Optional[int] = None) -> str:
    value = html.unescape(value or "")
    value = BeautifulSoup(value, "html.parser").get_text(" ", strip=True)
    value = re.sub(r"\s+", " ", value).strip()
    if limit and len(value) > limit:
        return value[: limit - 1].rstrip() + "..."
    return value


def parse_datetime(entry) -> dt.datetime:
    for key in ("published", "updated", "created"):
        raw = entry.get(key)
        if raw:
            try:
                parsed = parsedate_to_datetime(raw)
                if parsed.tzinfo is None:
                    return parsed.replace(tzinfo=dt.timezone.utc)
                return parsed.astimezone(dt.timezone.utc)
            except (TypeError, ValueError):
                pass
    return dt.datetime.now(dt.timezone.utc)


def score_item(title: str, summary: str, source_weight: int, published: dt.datetime) -> int:
    text = f"{title} {summary}".lower()
    score = source_weight
    score += sum(9 for word in REGIONAL_KEYWORDS if word in text)
    score += sum(6 for word in CRITICAL_KEYWORDS if word in text)

    age_hours = (dt.datetime.now(dt.timezone.utc) - published).total_seconds() / 3600
    if age_hours <= 12:
        score += 8
    elif age_hours <= 24:
        score += 5
    elif age_hours <= 48:
        score += 2

    cve_count = len(set(re.findall(r"CVE-\d{4}-\d{4,7}", text, re.IGNORECASE)))
    score += min(cve_count * 4, 12)
    return score


def score_ai_item(title: str, summary: str, source_weight: int, published: dt.datetime) -> int:
    text = f"{title} {summary}".lower()
    score = source_weight
    score += sum(5 for word in AI_PRIORITY_KEYWORDS if word in text)

    if any(word in text for word in ("launch", "release", "introducing", "announces", "unveils")):
        score += 5
    if any(word in text for word in ("research", "paper", "study", "benchmark", "eval")):
        score += 4

    age_hours = (dt.datetime.now(dt.timezone.utc) - published).total_seconds() / 3600
    if age_hours <= 12:
        score += 8
    elif age_hours <= 24:
        score += 5
    elif age_hours <= 48:
        score += 2

    return score


def vendor_hint(title: str) -> str:
    title_lower = title.lower()
    vendors = [
        "Apache HTTP Server",
        "Google Chrome",
        "Oracle PeopleSoft",
        "Microsoft Windows BitLocker",
        "Microsoft Windows Defender",
        "Palo Alto",
        "Fortinet",
        "Ivanti",
        "VMware",
        "Splunk Enterprise",
    ]
    for vendor in vendors:
        if vendor.lower() in title_lower:
            return vendor
    match = re.search(r":\s*(.+?)(?:\s+中的|\s+in\s+)", title, re.IGNORECASE)
    return match.group(1) if match else "affected product"


def fetch_rss_source(source: dict, scoring_fn=score_item) -> list[NewsItem]:
    parsed = feedparser.parse(source["url"])
    items = []
    for entry in parsed.entries[:30]:
        title = clean_text(entry.get("title", ""))
        link = entry.get("link", "")
        summary = clean_text(entry.get("summary", entry.get("description", "")), 360)
        if not title or not link:
            continue
        published = parse_datetime(entry)
        score = scoring_fn(title, summary, int(source["weight"]), published)
        items.append(NewsItem(title, summary, link, source["name"], published, score))
    return items


def fetch_govcert_hk(source: dict) -> list[NewsItem]:
    response = requests.get(source["url"], timeout=20)
    response.raise_for_status()
    soup = BeautifulSoup(response.text, "html.parser")
    items = []
    for anchor in soup.select("a[href*='alerts_detail.php']")[:20]:
        title = clean_text(anchor.get_text(" ", strip=True))
        href = anchor.get("href", "")
        if not title or not href:
            continue
        link = requests.compat.urljoin(source["url"], href)
        vendor = vendor_hint(title)
        threat_level = "high-threat " if "high threat" in title.lower() or "高威脅" in title else ""
        summary = (
            f"GovCERT.HK issued a {threat_level}security alert for {vendor}. "
            "Administrators should review exposure, apply vendor patches, and monitor affected systems."
        )
        published = dt.datetime.now(dt.timezone.utc)
        score = score_item(title, summary, int(source["weight"]), published)
        items.append(NewsItem(title, summary, link, source["name"], published, score))
    return items


def fetch_items(sources: list[dict], scoring_fn=score_item) -> list[NewsItem]:
    all_items: list[NewsItem] = []
    for source in sources:
        try:
            if source.get("kind") == "govcert_hk":
                all_items.extend(fetch_govcert_hk(source))
            else:
                all_items.extend(fetch_rss_source(source, scoring_fn=scoring_fn))
        except Exception as exc:
            print(f"Warning: failed to fetch {source['name']}: {exc}", file=sys.stderr)
    return all_items


def dedupe(items: Iterable[NewsItem]) -> list[NewsItem]:
    seen = set()
    unique = []
    for item in sorted(items, key=lambda item: item.score, reverse=True):
        title_key = normalized_title(item.title)
        domain = urlparse(item.link).netloc.lower()
        key = (domain, title_key[:90])
        if key in seen or item.link in seen:
            continue
        seen.add(key)
        seen.add(item.link)
        unique.append(item)
    return unique


def item_fingerprint(item: NewsItem) -> str:
    domain = urlparse(item.link).netloc.lower()
    return f"{domain}|{normalized_title(item.title)[:160]}"


def load_state(path: Path) -> dict:
    if not path.exists():
        return {}
    try:
        payload = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        return {}
    if "security" in payload or "ai" in payload:
        return payload
    if "last_digest_date" in payload or "last_digest_fingerprints" in payload:
        return {
            "security": {
                "last_digest_date": payload.get("last_digest_date"),
                "last_digest_fingerprints": payload.get("last_digest_fingerprints", []),
            }
        }
    return payload


def save_state(path: Path, payload: dict) -> None:
    path.write_text(json.dumps(payload, ensure_ascii=False, indent=2, sort_keys=True) + "\n", encoding="utf-8")


def filter_previous_digest_items(
    items: Iterable[NewsItem],
    state: dict,
    timezone_name: str,
) -> list[NewsItem]:
    tz = ZoneInfo(timezone_name)
    today = dt.datetime.now(tz).date()
    yesterday = (today - dt.timedelta(days=1)).isoformat()
    if state.get("last_digest_date") != yesterday:
        return list(items)

    previous_fingerprints = set(state.get("last_digest_fingerprints", []))
    if not previous_fingerprints:
        return list(items)

    return [item for item in items if item_fingerprint(item) not in previous_fingerprints]


def select_top_items(
    items: list[NewsItem],
    max_items: int,
    lookback_hours: int,
    state: dict,
    timezone_name: str,
) -> list[NewsItem]:
    cutoff = dt.datetime.now(dt.timezone.utc) - dt.timedelta(hours=lookback_hours)
    recent = [item for item in items if item.published >= cutoff]
    candidates = recent if len(recent) >= max_items else items
    candidates = filter_previous_digest_items(dedupe(candidates), state, timezone_name)
    selected = []
    source_counts = {}
    for item in candidates:
        count = source_counts.get(item.source, 0)
        if count >= 3 and len(selected) < max_items - 2:
            continue
        selected.append(item)
        source_counts[item.source] = count + 1
        if len(selected) == max_items:
            break
    return selected


def translate(text: str, translator: GoogleTranslator) -> str:
    text = clean_text(text, 900)
    if not text:
        return ""
    for _ in range(3):
        try:
            translated = translator.translate(text)
            if translated and "Error 500" not in translated and "That’s an error" not in translated:
                return translated
        except Exception:
            time.sleep(1)
    return text


def analyst_summary(item: NewsItem, translated_summary: str) -> str:
    text = f"{item.title} {item.summary}".lower()
    concerns = []

    if any(word in text for word in ("hong kong", "hkcert", "govcert.hk", "hksar")):
        concerns.append("香港機構應優先留意")
    if any(word in text for word in ("china", "chinese", "beijing")):
        concerns.append("涉及中國或中國相關威脅活動")
    if any(word in text for word in ("zero-day", "zero day", "actively exploited", "exploited")):
        concerns.append("可能已遭實際利用")
    if any(word in text for word in ("critical", "rce", "remote code execution")):
        concerns.append("存在高危或遠端程式碼執行風險")
    if "ransomware" in text:
        concerns.append("與勒索軟件風險相關")
    if any(word in text for word in ("data breach", "breach", "leak")):
        concerns.append("可能涉及資料外洩")
    if any(word in text for word in ("vpn", "firewall", "edge device", "router", "gateway")):
        concerns.append("邊界設備或遠端存取系統風險較高")

    base = clean_text(translated_summary, 260)
    if not concerns:
        return base
    finding = "；".join(dict.fromkeys(concerns))
    if base:
        return f"{base} 重點評估：{finding}。"
    return f"重點評估：{finding}。"


def ai_analyst_summary(item: NewsItem, translated_summary: str) -> str:
    text = f"{item.title} {item.summary}".lower()
    concerns = []

    if any(word in text for word in ("openai", "anthropic", "google", "meta", "microsoft", "nvidia")):
        concerns.append("涉及主要 AI 廠商動向")
    if any(word in text for word in ("launch", "release", "introducing", "announces", "unveils")):
        concerns.append("屬於新產品或新模型發布")
    if any(word in text for word in ("research", "paper", "study", "benchmark", "eval")):
        concerns.append("包含研究或評測重點")
    if any(word in text for word in ("agent", "agents", "copilot", "assistant", "workflow")):
        concerns.append("與 AI 代理或生產力應用相關")
    if any(word in text for word in ("safety", "policy", "regulation", "governance", "alignment")):
        concerns.append("涉及安全、政策或治理議題")

    base = clean_text(translated_summary, 260)
    if not concerns:
        return base
    finding = "；".join(dict.fromkeys(concerns))
    if base:
        return f"{base} 重點評估：{finding}。"
    return f"重點評估：{finding}。"


def build_digest(items: list[NewsItem], timezone_name: str, digest_title: str, summary_fn=analyst_summary) -> str:
    tz = ZoneInfo(timezone_name)
    today = dt.datetime.now(tz).strftime("%Y年%m月%d日")
    translator = GoogleTranslator(source="auto", target="zh-TW")
    lines = [f"{digest_title} - {today}", ""]

    if not items:
        lines.append("今天沒有新的未重複網絡安全新聞。")
        return "\n".join(lines).strip()

    for index, item in enumerate(items, start=1):
        title_zh = translate(item.title, translator)
        translated_summary = translate(item.summary or item.title, translator)
        summary_zh = summary_fn(item, translated_summary)
        summary_en = clean_text(item.summary or item.title, 420)
        lines.extend(
            [
                f"{index}.",
                f"• {title_zh}",
                f"• 摘要：{summary_zh}",
                f"• 英文摘要：{summary_en}",
                f"• 來源連結：{item.link}",
                "",
            ]
        )
    return "\n".join(lines).strip()


def split_telegram_messages(text: str, limit: int = 3900) -> list[str]:
    messages = []
    current = ""
    for block in text.split("\n\n"):
        candidate = f"{current}\n\n{block}".strip() if current else block
        if len(candidate) > limit and current:
            messages.append(current)
            current = block
        else:
            current = candidate
    if current:
        messages.append(current)
    return messages


def send_telegram(text: str, bot_token: str, chat_id: str) -> None:
    url = f"https://api.telegram.org/bot{bot_token}/sendMessage"
    for message in split_telegram_messages(text):
        response = requests.post(
            url,
            json={
                "chat_id": chat_id,
                "text": message,
                "disable_web_page_preview": True,
            },
            timeout=20,
        )
        response.raise_for_status()
        time.sleep(0.5)


def get_recent_chats(bot_token: str) -> list[dict]:
    url = f"https://api.telegram.org/bot{bot_token}/getUpdates"
    response = requests.get(url, timeout=20)
    response.raise_for_status()
    data = response.json()
    chats = []
    for update in data.get("result", [])[-20:]:
        message = update.get("message") or update.get("channel_post") or {}
        chat = message.get("chat") or {}
        if chat.get("id"):
            chats.append(chat)
    return chats


def print_chat_id(bot_token: str) -> None:
    chats = get_recent_chats(bot_token)
    if not chats:
        print("No Telegram updates found. Send /start to the bot in Telegram once, then run this again.")
        return
    for chat in chats:
        print(
            f"chat_id={chat['id']} type={chat.get('type')} "
            f"title={chat.get('title') or chat.get('username') or chat.get('first_name')}"
        )


def resolve_chat_id(bot_token: str, chat_id: str) -> str:
    if chat_id:
        return chat_id

    chats = get_recent_chats(bot_token)
    private_chats = [chat for chat in chats if chat.get("type") == "private" and chat.get("id")]
    if private_chats:
        latest_private_chat = private_chats[-1]
        resolved_chat_id = str(latest_private_chat["id"])
        print(
            f"Info: TELEGRAM_CHAT_ID not set; using latest private chat_id={resolved_chat_id}.",
            file=sys.stderr,
        )
        return resolved_chat_id

    unique_chat_ids = {str(chat["id"]) for chat in chats if chat.get("id")}
    if len(unique_chat_ids) == 1:
        resolved_chat_id = next(iter(unique_chat_ids))
        print(
            f"Info: TELEGRAM_CHAT_ID not set; using the only recent chat_id={resolved_chat_id}.",
            file=sys.stderr,
        )
        return resolved_chat_id

    raise SystemExit(
        "TELEGRAM_CHAT_ID is required. Send /start to the bot once, then either set TELEGRAM_CHAT_ID "
        "or rerun when the bot has exactly one recent target chat."
    )


def main() -> None:
    load_dotenv()
    parser = argparse.ArgumentParser(description="Send a daily AI or cybersecurity news digest to Telegram.")
    parser.add_argument("--dry-run", action="store_true", help="Print the digest without sending it.")
    parser.add_argument("--get-chat-id", action="store_true", help="Print recent Telegram chat IDs for the bot.")
    parser.add_argument("--topic", choices=("security", "ai"), default=os.getenv("NEWS_TOPIC", "security").strip().lower())
    args = parser.parse_args()

    bot_token = os.getenv("TELEGRAM_BOT_TOKEN", "").strip()
    chat_id = os.getenv("TELEGRAM_CHAT_ID", "").strip()
    timezone_name = os.getenv("NEWS_TIMEZONE", "Asia/Hong_Kong").strip()
    max_items = int(os.getenv("NEWS_MAX_ITEMS", "10"))
    lookback_hours = int(os.getenv("NEWS_LOOKBACK_HOURS", "72"))
    state_file = Path(os.getenv("NEWS_STATE_FILE", ".news_state.json")).expanduser()
    state = load_state(state_file)
    if args.topic == "ai":
        sources = AI_SOURCES
        digest_builder = ai_analyst_summary
        scoring_fn = score_ai_item
        state_key = "ai"
        default_title = "AI 每日情報摘要"
    else:
        sources = DEFAULT_SOURCES
        digest_builder = analyst_summary
        scoring_fn = score_item
        state_key = "security"
        default_title = "網絡安全每日情報摘要"
    digest_title = os.getenv("NEWS_TITLE", default_title).strip()

    if args.get_chat_id:
        if not bot_token:
            raise SystemExit("TELEGRAM_BOT_TOKEN is required.")
        print_chat_id(bot_token)
        return

    topic_state = state.get(state_key, {})
    items = select_top_items(fetch_items(sources, scoring_fn=scoring_fn), max_items, lookback_hours, topic_state, timezone_name)

    digest = build_digest(items, timezone_name, digest_title, summary_fn=digest_builder)
    if args.dry_run:
        print(digest)
        return

    if not bot_token:
        raise SystemExit("TELEGRAM_BOT_TOKEN is required.")
    chat_id = resolve_chat_id(bot_token, chat_id)
    send_telegram(digest, bot_token, chat_id)
    tz = ZoneInfo(timezone_name)
    save_state(
        state_file,
        {
            **state,
            state_key: {
                "last_digest_date": dt.datetime.now(tz).date().isoformat(),
                "last_digest_fingerprints": [item_fingerprint(item) for item in items],
            },
        },
    )


if __name__ == "__main__":
    main()
