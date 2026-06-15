#!/usr/bin/env python3
import argparse
import datetime as dt
import html
import os
import re
import sys
import time
from dataclasses import dataclass
from email.utils import parsedate_to_datetime
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


@dataclass(frozen=True)
class NewsItem:
    title: str
    summary: str
    link: str
    source: str
    published: dt.datetime
    score: int


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


def fetch_rss_source(source: dict) -> list[NewsItem]:
    parsed = feedparser.parse(source["url"])
    items = []
    for entry in parsed.entries[:30]:
        title = clean_text(entry.get("title", ""))
        link = entry.get("link", "")
        summary = clean_text(entry.get("summary", entry.get("description", "")), 360)
        if not title or not link:
            continue
        published = parse_datetime(entry)
        score = score_item(title, summary, int(source["weight"]), published)
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


def fetch_items() -> list[NewsItem]:
    all_items: list[NewsItem] = []
    for source in DEFAULT_SOURCES:
        try:
            if source.get("kind") == "govcert_hk":
                all_items.extend(fetch_govcert_hk(source))
            else:
                all_items.extend(fetch_rss_source(source))
        except Exception as exc:
            print(f"Warning: failed to fetch {source['name']}: {exc}", file=sys.stderr)
    return all_items


def dedupe(items: Iterable[NewsItem]) -> list[NewsItem]:
    seen = set()
    unique = []
    for item in sorted(items, key=lambda item: item.score, reverse=True):
        normalized_title = re.sub(r"[^a-z0-9]+", " ", item.title.lower()).strip()
        domain = urlparse(item.link).netloc.lower()
        key = (domain, normalized_title[:90])
        if key in seen or item.link in seen:
            continue
        seen.add(key)
        seen.add(item.link)
        unique.append(item)
    return unique


def select_top_items(items: list[NewsItem], max_items: int, lookback_hours: int) -> list[NewsItem]:
    cutoff = dt.datetime.now(dt.timezone.utc) - dt.timedelta(hours=lookback_hours)
    recent = [item for item in items if item.published >= cutoff]
    candidates = recent if len(recent) >= max_items else items
    selected = []
    source_counts = {}
    for item in dedupe(candidates):
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


def build_digest(items: list[NewsItem], timezone_name: str) -> str:
    tz = ZoneInfo(timezone_name)
    today = dt.datetime.now(tz).strftime("%Y年%m月%d日")
    translator = GoogleTranslator(source="auto", target="zh-TW")
    lines = [f"網絡安全每日情報摘要 - {today}", ""]

    for index, item in enumerate(items, start=1):
        title_zh = translate(item.title, translator)
        translated_summary = translate(item.summary or item.title, translator)
        summary_zh = analyst_summary(item, translated_summary)
        lines.extend(
            [
                f"{index}.",
                f"• {title_zh}",
                f"• 摘要：{summary_zh}",
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


def print_chat_id(bot_token: str) -> None:
    url = f"https://api.telegram.org/bot{bot_token}/getUpdates"
    response = requests.get(url, timeout=20)
    response.raise_for_status()
    data = response.json()
    if not data.get("result"):
        print("No Telegram updates found. Send /start to the bot in Telegram, then run this again.")
        return
    for update in data["result"][-10:]:
        message = update.get("message") or update.get("channel_post") or {}
        chat = message.get("chat") or {}
        if chat.get("id"):
            print(f"chat_id={chat['id']} type={chat.get('type')} title={chat.get('title') or chat.get('username') or chat.get('first_name')}")


def main() -> None:
    load_dotenv()
    parser = argparse.ArgumentParser(description="Send a daily cybersecurity news digest to Telegram.")
    parser.add_argument("--dry-run", action="store_true", help="Print the digest without sending it.")
    parser.add_argument("--get-chat-id", action="store_true", help="Print recent Telegram chat IDs for the bot.")
    args = parser.parse_args()

    bot_token = os.getenv("TELEGRAM_BOT_TOKEN", "").strip()
    chat_id = os.getenv("TELEGRAM_CHAT_ID", "").strip()
    timezone_name = os.getenv("NEWS_TIMEZONE", "Asia/Hong_Kong").strip()
    max_items = int(os.getenv("NEWS_MAX_ITEMS", "10"))
    lookback_hours = int(os.getenv("NEWS_LOOKBACK_HOURS", "72"))

    if args.get_chat_id:
        if not bot_token:
            raise SystemExit("TELEGRAM_BOT_TOKEN is required.")
        print_chat_id(bot_token)
        return

    items = select_top_items(fetch_items(), max_items, lookback_hours)
    if not items:
        raise SystemExit("No news items were found.")

    digest = build_digest(items, timezone_name)
    if args.dry_run:
        print(digest)
        return

    if not bot_token or not chat_id:
        raise SystemExit("TELEGRAM_BOT_TOKEN and TELEGRAM_CHAT_ID are required.")
    send_telegram(digest, bot_token, chat_id)


if __name__ == "__main__":
    main()
