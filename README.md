# Telegram News Feeds

Daily AI and cybersecurity intelligence digests for Telegram, formatted in Traditional Chinese.

## What it does

- Collects security news from global and Hong Kong-focused sources.
- Collects AI news from leading vendor, research, and industry sources.
- Prioritizes Hong Kong, China, actively exploited vulnerabilities, ransomware, supply-chain threats, and major vendor advisories.
- Supports a dedicated AI topic mode with separate source selection and scoring.
- Selects the top 10 items.
- Skips items already sent in the previous day's digest.
- Translates titles and snippets into Traditional Chinese.
- Includes the original English summary for cross-checking.
- Sends the digest to a Telegram private chat.
- Supports rebranding the digest title through `NEWS_TITLE` so you can reuse the same feed for a different bot.

## Required Telegram setup

1. Open Telegram and send `/start` to your bot once.
2. Copy `.env.example` to `.env`.
3. Add your bot token to `.env`.
4. Run:

```bash
python3 -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
TELEGRAM_BOT_TOKEN="your_bot_token" python cyber_news_feed.py --get-chat-id
```

5. Copy the numeric `chat_id` into `.env` as `TELEGRAM_CHAT_ID`.

Private Telegram chats require the numeric `chat_id`. A username such as `helloworld423` is not enough for Bot API delivery.
If `TELEGRAM_CHAT_ID` is not set, the script will try to use the latest recent private chat automatically after that one-time `/start`.

To reuse the same feed for your new bot, set:

```bash
TELEGRAM_BOT_TOKEN="your_new_bot_token"
TELEGRAM_CHAT_ID="your_numeric_chat_id"
NEWS_TITLE="AI News Daily Digest"
```

## Run locally

Preview without sending:

```bash
python cyber_news_feed.py --dry-run
```

Preview AI news:

```bash
python cyber_news_feed.py --topic ai --dry-run
```

Send to Telegram:

```bash
python cyber_news_feed.py
```

Send AI news to Telegram:

```bash
NEWS_TOPIC=ai NEWS_TITLE="AI 每日情報摘要" python cyber_news_feed.py
```

## GitHub Actions setup

The security workflow runs every day at 08:07 Hong Kong time.
The AI workflow runs every day at 08:17 Hong Kong time.
The delivery runs on GitHub Actions, so your Mac does not need to be powered on at that time.
After `TELEGRAM_BOT_TOKEN` and `TELEGRAM_CHAT_ID` are stored in GitHub repository secrets, daily delivery is fully automated.
The workflows also store a small state file in the repository so the next day's digest can avoid repeating items already sent yesterday for each topic independently.

Add these GitHub repository secrets:

- `TELEGRAM_BOT_TOKEN`
- `TELEGRAM_CHAT_ID`

Then enable GitHub Actions for the repository. You can also run the workflow manually from the Actions tab.

## Notes

- Telegram Bot delivery is free.
- GitHub Actions is free within GitHub's free usage limits.
- Translation uses a free machine-translation package. It is suitable for daily scanning, but not a substitute for human-edited intelligence reporting.
