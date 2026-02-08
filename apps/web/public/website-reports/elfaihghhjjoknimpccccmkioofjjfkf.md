# StayFree (elfaihghhjjoknimpccccmkioofjjfkf) - Vulnerability Report

## Executive Summary

StayFree v2.5.6 is a "website blocker & screen time tracker" extension that is owned by **Sensor Tower**, a mobile/web analytics and ad intelligence company. While it provides legitimate productivity features (website blocking, usage limits, keyword blocking, in-app social media blocking), it embeds an extensive data collection infrastructure that goes significantly beyond its stated purpose as a time tracker:

1. **Sensor Tower's Pathmatics ad intelligence SDK** (`@sensortower/ad-finder`) -- hooks `XMLHttpRequest.prototype.send` and `window.fetch` globally to intercept ALL HTTP response bodies on visited pages, scraping ad creatives from YouTube, Hulu, Netflix, TikTok, Twitter/X, and all VAST-compliant ad networks.
2. **Gen-AI conversation metadata collection** -- scrapes ChatGPT, Gemini, Claude, Copilot, DeepSeek, Perplexity, Grok, and Amazon Rufus conversations. Sends metadata (timestamps, service, model, subscription plan, conversation order) to `https://api.stayfreeapps.com/v1/ai/analytics`. Also uploads actual URLs from AI responses to `/v1/ai/links` and full markdown content of AI interaction cards to `/v1/ai/interactions`.
3. **Chatbot interaction scraping** -- detects and scrapes conversations from 30+ customer service chatbot widgets (Intercom, Zendesk, Drift, Gorgias, Sierra, Agentforce, etc.) including actual chat content, uploaded to `/v1/ai/chatbot_chats`.
4. **Browsing data upload pipeline** -- per-website session durations, page view timestamps, ad network attribution (UTM params, referrers), uploaded to `https://api.stayfreeapps.com/v1/web/upload` and `/v1/page_views/upload`.
5. **URL query parameter collection** -- search queries and URL parameters from visited websites, uploaded to `/v1/query_params/upload`.
6. **Retail ad scraping** -- product ads from shopping sites (Amazon, Instacart) including sponsored product details, uploaded to `/v1/desktop/retail/{website}`.
7. **LZ-String compression library** bundled in all content scripts (the "data_compression_exfil" flags).
8. **Google Analytics (GA4) Measurement Protocol** telemetry sent from the background script.
9. **Remote configuration** fetched from `https://api.stayfreeapps.com/v1/remote_config/stayfree-chrome` enabling server-controlled behavior changes.

The extension has a consent mechanism: during onboarding, users see a privacy slide with a checkbox. Data uploads are gated by `hasAcceptedDataCollection === "accepted"` AND `hasAcceptedTos === true` AND `age >= 18`. There is also an opt-out API endpoint. However, the checkbox is pre-checked (`m = O(!0)`, `p = O(!0)` in `onboarding-DoXiXPDK.js:768-769`), and the scope of data collection is not clearly communicated to users through the consent UI.

**This extension is a sibling product to StayFocusd (laankejkbhbdhmipfmgcngdelahlfoji)**, sharing identical codebase, API infrastructure, and Sensor Tower SDK. The `pageViewIgnoreList` even references `stayfocusd.com`.

**Overall Risk Assessment: MEDIUM-HIGH**

---

## Architecture Overview

| Component | File | Purpose |
|---|---|---|
| Background service worker | `background.js` (166K lines) | Session tracking, upload orchestration, Pathmatics SDK host, remote config, GA4 |
| Ad finder content script | `content-scripts/ad-finder.js` (161K lines) | `@sensortower/ad-finder` Pathmatics SDK, display ad detection via CSS rule engine |
| Gen-AI collector | `content-scripts/gen-ai-collector.js` (159K lines) | Scrapes ChatGPT/Gemini/Claude/Copilot/DeepSeek/Perplexity/Grok/Amazon Rufus |
| Chatbot finder | `content-scripts/chatbot-finder.js` (158K lines) | Detects and scrapes 30+ customer service chatbot widgets |
| Usage monitoring | `content-scripts/usage-monitoring.js` (156K lines) | Tracks time spent per website, page visibility |
| Block website | `content-scripts/block-website.js` (193K lines) | Website blocking overlay, contains full API client |
| Keyword blocking | `content-scripts/keyword-blocking.js` (192K lines) | Keyword-based content blocking |
| In-app blocking | `content-scripts/in-app-blocking.js` (145K lines) | Social media feature blocking (YouTube Shorts, TikTok, etc.) |
| Auto-connect redirect | `content-scripts/auto-connect-redirect.js` (1.4K lines) | Device pairing redirect handler |
| Pathmatics injected script | Embedded string in `background.js:16982` & `gen-ai-collector.js:154599` | XHR/fetch hook for ad response interception |

### Data Flow Architecture

```
User's Browser
    |
    +-- content-scripts/ad-finder.js (on ALL pages)
    |       |-- Injects Pathmatics script into page context
    |       |-- Hooks XMLHttpRequest.send + window.fetch
    |       |-- Scrapes ad creatives from YouTube/Hulu/Netflix/TikTok/Twitter
    |       +-- uploadRetailAds() -> POST /v1/desktop/retail/{website}
    |
    +-- content-scripts/gen-ai-collector.js (on ALL pages)
    |       |-- Polls AI chat pages every 10 seconds
    |       |-- Scrapes prompts, responses, URLs via CSS selectors
    |       |-- uploadGenAiChats() -> POST /v1/ai/analytics (metadata only)
    |       |-- uploadGenAiLinks() -> POST /v1/ai/links (actual URLs)
    |       +-- uploadGenAiInteractions() -> POST /v1/ai/interactions (markdown content)
    |
    +-- content-scripts/chatbot-finder.js (on ALL pages, all_frames: true)
    |       |-- Detects chatbot widgets (Intercom, Zendesk, etc.)
    |       |-- uploadChatbots() -> POST /v1/ai/chatbot
    |       +-- uploadChatbotChats() -> POST /v1/ai/chatbot_chats (actual chat content)
    |
    +-- background.js (service worker)
            |-- Sessions: POST /v1/web/upload (per-site durations)
            |-- Page views: POST /v1/page_views/upload (timestamps, durations, referrers, UTMs)
            |-- Query params: POST /v1/query_params/upload (URL search params)
            |-- Subscription status: POST /v1/subscriptions/status
            |-- GA4: POST google-analytics.com/mp/collect
            +-- Remote config: GET /v1/remote_config/stayfree-chrome
```

All API requests go to `https://api.stayfreeapps.com`.

---

## Vulnerability Analysis

### VULN-01: XHR/Fetch Interception for Ad Intelligence Scraping
**Severity: HIGH (CVSS 7.5)** -- AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:N/A:N

**Files:**
- `background.js:16982` -- Pathmatics script embedded as string literal
- `content-scripts/gen-ai-collector.js:154599` -- Same Pathmatics script
- `content-scripts/ad-finder.js:158366-158370` -- Pathmatics injection entry point

**Description:**
The Sensor Tower Pathmatics ad intelligence script is injected into page contexts via a `<script>` element. It globally monkey-patches `XMLHttpRequest.prototype.send` and replaces `window.fetch` to intercept ALL successful HTTP responses (status 200-210) with text/JSON/XML/JavaScript content types.

The XHR hook (from embedded Pathmatics script):
```javascript
var i = XMLHttpRequest.prototype.send;
function s() {
    var f = this.onreadystatechange, p = arguments;
    this.onreadystatechange = function(m) {
        return r(m, this), f?.apply?.(this, arguments)
    };
    i.apply(this, p);
}
XMLHttpRequest.prototype.send = s;
```

The fetch hook:
```javascript
var u = C.fetch;
var l = function() {
    return u.apply(this, arguments).then(async f => {
        var p = f.headers.get("Content-Type");
        if (p && (p.includes("text") || p.includes("json") ||
            p.includes("xml") || p.includes("javascript"))) {
            var m = f.clone(), g = await m.text();
            e(g, null, p.includes("json"), m.url);
        }
        return f;
    });
};
C.fetch = l;
```

This intercepts ALL network traffic content on pages where it is activated. The intercepted data is then parsed for ad-related content from YouTube, Hulu, Netflix, TikTok, and Twitter/X. While it targets ad content specifically, the hook captures ALL responses first before filtering.

The Pathmatics SDK uses a percentage-based rollout (`EnabledPct`) controlled via external configuration, meaning Sensor Tower can remotely enable/disable this for subsets of users.

**PoC Scenario:**
1. Install StayFree extension, accept terms during onboarding
2. Visit youtube.com and play a video with ads
3. The Pathmatics script hooks XHR/fetch, intercepts the YouTube ad break API response
4. Ad creative data (video IDs, click-through URLs, advertiser info) is extracted and sent to Sensor Tower

---

### VULN-02: AI Conversation Metadata and Content Exfiltration
**Severity: HIGH (CVSS 7.1)** -- AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:N/A:N

**Files:**
- `content-scripts/gen-ai-collector.js:157298-157670` -- AI service parser configs
- `content-scripts/gen-ai-collector.js:157041-157138` -- Data extraction and upload logic (`nx()`)
- `content-scripts/gen-ai-collector.js:156999-157011` -- Polling loop (every 10 seconds)
- `content-scripts/gen-ai-collector.js:5227-5261` -- API upload functions

**Description:**
The `gen-ai-collector.js` content script runs on ALL pages (`matches: ["*://*/*"]`) and contains detailed CSS selector configurations for scraping AI chat services:

| Service | Hostname | Prompts Selector | Responses Selector |
|---|---|---|---|
| ChatGPT | chatgpt.com | `div[data-message-author-role="user"]` | `div[data-message-author-role="assistant"]` |
| Gemini | gemini.google.com | `user-query .query-text` | `model-response .model-response-text` |
| Claude | claude.ai | `[data-testid="user-message"] p` | `.font-claude-response .standard-markdown` |
| Copilot | copilot.microsoft.com | `[data-content="user-message"]` | `[data-content="ai-message"]` |
| DeepSeek | chat.deepseek.com | `._9663006 .fbb737a4` | `.ds-markdown` |
| Perplexity | perplexity.ai | `[data-lexical-editor="true"] span` | `[id^="markdown-content-"]` |
| Grok | grok.com | `div.items-end div.message-bubble span` | `div.items-start div.message-bubble div.response-content-markdown` |
| Grok (X.com) | x.com | CSS class selectors | CSS class selectors |
| Amazon Rufus | amazon.com | `[data-section-class="CustomerText"]` | `[data-section-class="TextSubsections"]` |
| Google AI Search | google.com | - | AI overview citation links |

The collector polls every 10 seconds (`i.pollInterval ?? 10 * xo`) after an initial delay. Data uploaded:

1. **`/v1/ai/analytics`** (metadata): timestamp, service name, prompt_or_response type, conversation_id (hash of URL), conversation_order, model name, subscription_plan. **Does NOT include actual prompt/response text** -- uses hashes for deduplication.
2. **`/v1/ai/links`** (actual URLs): URLs found in AI responses with link ordering.
3. **`/v1/ai/interactions`** (actual content): For ChatGPT interactions (shopping, design, image generation), the full markdown content of interaction cards is extracted via `turndown(innerHTML)` and sent as `interaction_details`.

Additionally, user subscription status (free/premium/guest) for each AI service is detected via CSS selectors and uploaded to `/v1/subscriptions/status`.

**Forbidden words filter:** Content containing "drug", "alcohol", or "porn" is excluded (`forbiddenPromptWords: ["drug", "alcohol", "porn"]` at line 157296).

**PoC Scenario:**
1. Install StayFree, accept terms
2. Visit chatgpt.com and have a conversation about a business strategy
3. The collector scrapes conversation metadata (model, order, timestamps) and any URLs in responses
4. For ChatGPT shopping interactions, actual product card content is scraped and uploaded
5. Data is sent to `https://api.stayfreeapps.com/v1/ai/analytics` with the user's install_id

---

### VULN-03: Customer Service Chatbot Content Scraping
**Severity: MEDIUM-HIGH (CVSS 6.5)** -- AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:N/A:N

**Files:**
- `content-scripts/chatbot-finder.js` -- Main chatbot detection and scraping
- `content-scripts/gen-ai-collector.js:157827-158160` -- Chatbot widget selectors
- `content-scripts/gen-ai-collector.js:5263-5293` -- Chatbot upload APIs

**Description:**
The extension detects and scrapes conversations from 30+ commercial chatbot widgets embedded on websites:

Intercom, Zendesk, Drift, Gorgias, Sierra, Agentforce (Salesforce), Shopify Inbox, Gupshup, ElevenLabs, Kustomer, Big Sur AI, Gladly, Retell AI, and more.

Chat content (user messages and bot responses) is uploaded to:
- `/v1/ai/chatbot` -- Chatbot detection metadata (hostname, path, service)
- `/v1/ai/chatbot_chats` -- Actual chat content including `chats` array with user messages and responses

This means that private customer service conversations (order issues, account problems, medical inquiries on health sites) could be collected.

---

### VULN-04: Browsing History and Search Query Collection
**Severity: MEDIUM (CVSS 5.3)** -- AV:N/AC:L/PR:N/UI:R/S:U/C:L/I:N/A:N

**Files:**
- `background.js:15658-15675` -- Page view upload payload construction
- `background.js:20030-20079` -- Web usage and page view upload API calls
- `background.js:5295-5307` (gen-ai-collector equivalent) -- Query params upload

**Description:**
The extension uploads detailed browsing data:

**Web usage** (`/v1/web/upload`): Per-website session durations with `diff_private_websites` field (differential privacy applied), device name, OS type, birth year, timezone.

**Page views** (`/v1/page_views/upload`): Individual page view records including:
- `duration` -- time spent on each page
- `timestamp` -- when the page was visited
- `referrer` -- referring page URL
- `ad_network` -- detected ad network (Google, Facebook, Bing, etc.)
- `utm_source`, `utm_medium`, `utm_campaign`, `utm_term` -- marketing attribution params

**Query parameters** (`/v1/query_params/upload`): URL search parameters from visited websites, which can include search queries.

A `pageViewIgnoreList` excludes some sensitive sites (Google Docs, Gmail, Outlook, medical sites like WebMD/MayoClinic, StayFree/SensorTower own domains), but the default is to collect from all other sites.

The `uploadWebUsage` flag defaults to `false` in the hardcoded config but can be enabled via remote config from `https://api.stayfreeapps.com/v1/remote_config/shared-web-config`.

---

### VULN-05: Remote Configuration Enables Server-Controlled Behavior
**Severity: MEDIUM (CVSS 5.0)** -- AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:L/A:N

**Files:**
- `background.js:9460` -- `https://api.stayfreeapps.com/v1/remote_config/shared-web-config`
- `background.js:21387` -- `https://api.stayfreeapps.com/v1/remote_config/stayfree-chrome`
- `background.js:9434` -- `uploadWebUsage: false` (default)

**Description:**
The extension fetches remote configuration from Sensor Tower servers that can modify:
- `uploadWebUsage` -- toggle browsing data uploads (default false, can be remotely enabled)
- `pageViewIgnoreList` -- which sites to exclude from tracking
- `genAiParsers` -- AI chat scraping selector configurations (can be updated without extension update)
- `chatbotSelectors` -- chatbot detection selectors
- `adNetworks` -- ad network detection patterns
- `adFields` -- ad attribution field configurations
- `bugsnagIgnoreMatches` -- error reporting filters
- `lunaAdblockPromotion` -- cross-promotion of Luna ad blocker
- Pathmatics `EnabledPct` -- percentage-based rollout of ad scraping

This means Sensor Tower can remotely change what data is collected, which sites are targeted, and which users have ad scraping enabled, without requiring a Chrome Web Store update.

---

### VULN-06: Pre-Checked Consent with Inadequate Disclosure
**Severity: MEDIUM (CVSS 4.3)** -- AV:N/AC:L/PR:N/UI:R/S:U/C:N/I:L/A:N

**Files:**
- `chunks/onboarding-DoXiXPDK.js:768-769` -- Pre-checked consent checkboxes
- `chunks/onboarding-DoXiXPDK.js:771` -- Privacy consent handler
- `background.js:5329-5335` -- Consent gating function (`zr()`)

**Description:**
During onboarding, the privacy consent slide has two checkboxes that are both pre-checked (`O(!0)` = `ref(true)`):
```javascript
const m = O(!0),  // ToS checkbox - pre-checked
      p = O(!0);  // Data collection checkbox - pre-checked
```

Users must actively uncheck the data collection box to opt out. Under GDPR and many privacy regulations, consent for data collection must be affirmative (opt-in), not pre-selected.

The consent gate (`zr()`) requires: `hasAcceptedTos && hasAcceptedDataCollection === "accepted" && age >= 18`. While this gating exists and is applied to upload functions, the pre-checked nature of the consent undermines informed consent.

---

## False Positive Analysis

| Triage Flag | Count | Category | Verdict | Explanation |
|---|---|---|---|---|
| xhr_hook | 17 | T1 | **MIXED** | The XHR hooks are from the Pathmatics SDK (Sensor Tower ad intelligence), not for malicious hijacking. However, they DO intercept all HTTP response content on pages. TRUE POSITIVE for surveillance concern, but it's commercial ad intelligence, not traditional malware. |
| data_compression_exfil | 8 | T1 | **FALSE POSITIVE** | LZ-String library is bundled in every content script for local storage compression of extension state data (usage limits, preferences, blocked sites). It is NOT used for compressing exfiltrated data before upload. The API calls use standard JSON POST requests. |
| DOM scraping | varies | V1 | **MIXED** | querySelector calls are used for legitimate UI features (website blocking overlays, in-app blocking of YouTube Shorts/TikTok feeds), but ALSO for AI conversation scraping and chatbot detection. |
| webNavigation | - | V2 | **FALSE POSITIVE** | Used for legitimate session tracking (tracking which tab is active for usage time calculation). |
| innerHTML | - | V1 | **MIXED** | Used both for legitimate UI rendering (blocking overlays, dashboard) and for AI interaction content extraction via Turndown markdown conversion. |
| fetch/XMLHttpRequest | - | V2 | **TRUE POSITIVE** | The Pathmatics SDK replaces `window.fetch` and hooks `XMLHttpRequest.prototype.send` globally. Additionally, the extension's own API client makes numerous POST requests to stayfreeapps.com endpoints. |
| storage access | - | V2 | **FALSE POSITIVE** | Standard chrome.storage.local usage for preferences, session data, and usage limits. |

---

## Comparison with StayFocusd (laankejkbhbdhmipfmgcngdelahlfoji)

StayFree and StayFocusd share an **identical codebase** for their data collection infrastructure:

| Feature | StayFree | StayFocusd |
|---|---|---|
| Pathmatics SDK | Yes | Yes |
| Gen-AI collector | Yes (9 services) | Yes (ChatGPT, Gemini, DeepSeek, Perplexity, Copilot) |
| Chatbot scraping | Yes (30+ widgets) | Yes |
| XHR/fetch hooking | Yes | Yes |
| LZ-String | Yes (bundled in all CS) | Yes |
| API base | api.stayfreeapps.com | stayfocusd.st-panel-api.com |
| Remote config | stayfree-chrome endpoint | stayfocusd endpoint |
| WXT framework | Yes | Yes |
| BugSnag error reporting | Yes | Yes |
| GA4 Measurement Protocol | Yes | Yes |
| Consent mechanism | Pre-checked onboarding | ToS acceptance flow |
| pageViewIgnoreList | Includes `stayfocusd.com` | Includes `stayfreeapps.com` |

The `pageViewIgnoreList` in StayFree explicitly excludes `stayfocusd.com`, confirming these are sibling products.

---

## API Endpoint Summary

| Endpoint | Method | Data Sent | Purpose |
|---|---|---|---|
| `/v1/web/upload` | POST | Session durations per website, diff_private_websites, birth_year | Browsing history |
| `/v1/page_views/upload` | POST | Per-page durations, timestamps, referrers, UTM params, ad networks | Detailed page analytics |
| `/v1/ai/analytics` | POST | AI chat metadata (service, model, conversation_id, order, plan) | AI usage analytics |
| `/v1/ai/links` | POST | URLs from AI responses with ordering | AI link intelligence |
| `/v1/ai/interactions` | POST | Markdown content of AI interaction cards (shopping, DALL-E) | AI interaction content |
| `/v1/ai/chatbot` | POST | Chatbot widget detection (service, hostname, path, timestamp) | Chatbot market intelligence |
| `/v1/ai/chatbot_chats` | POST | Actual chatbot conversation content | Chatbot content collection |
| `/v1/query_params/upload` | POST | URL search parameters from visited websites | Search query intelligence |
| `/v1/desktop/retail/{site}` | POST | Sponsored product ad details from shopping sites | Retail ad intelligence |
| `/v1/subscriptions/status` | POST | AI service subscription status (free/premium/guest) | Market research |
| `/v1/analytics/optout` | GET | install_id, opt_out flag | Opt-out mechanism |
| `/v1/remote_config/stayfree-chrome` | GET | - | Fetch remote configuration |
| `/v1/remote_config/shared-web-config` | GET | - | Fetch shared configuration |

---

## Manifest Permissions Analysis

```json
{
  "permissions": ["alarms", "tabs", "storage", "notifications", "webNavigation", "scripting", "favicon", "search"],
  "optional_permissions": ["history", "downloads"],
  "host_permissions": ["*://*/*"],
  "content_scripts": [
    {"matches": ["*://*/*"], "all_frames": true, "run_at": "document_start", "js": ["content-scripts/ad-finder.js"]},
    {"matches": ["*://*/*"], "js": ["content-scripts/auto-connect-redirect.js", "content-scripts/gen-ai-collector.js"]},
    {"matches": ["*://*/*"], "run_at": "document_end", "js": ["content-scripts/block-website.js", "content-scripts/keyword-blocking.js", "content-scripts/usage-monitoring.js"]},
    {"matches": ["*://*/*"], "all_frames": true, "js": ["content-scripts/chatbot-finder.js"]},
    {"matches": ["*://*.facebook.com/*", ...social media sites...], "js": ["content-scripts/in-app-blocking.js"]}
  ]
}
```

- `*://*/*` host permissions grants access to ALL websites
- `all_frames: true` on ad-finder and chatbot-finder means these run in every iframe on every page
- `run_at: document_start` for ad-finder ensures the XHR/fetch hooks are installed before any page scripts run
- `scripting` permission allows dynamic script injection (used for Pathmatics script injection)
- 5 content scripts running on ALL pages creates significant performance overhead

---

## Overall Risk Assessment: MEDIUM-HIGH

### Justification

**Not HIGH because:**
- There IS a consent mechanism (even if pre-checked)
- AI chat content itself (prompts/responses) is NOT uploaded in plaintext for the main GenAI analytics -- only metadata
- The `uploadWebUsage` flag defaults to `false`
- The pageViewIgnoreList excludes some sensitive domains
- The extension provides legitimate, useful functionality

**MEDIUM-HIGH because:**
- The Pathmatics SDK hooks ALL XHR/fetch traffic, far exceeding what a time tracker needs
- AI interaction cards and chatbot conversations ARE uploaded with actual content
- URLs from AI responses are uploaded in plaintext
- Pre-checked consent undermines informed user choice
- The scope of data collection (ad intelligence, AI analytics, chatbot scraping, search queries) is fundamentally different from what users expect from a "website blocker"
- Remote configuration allows server-side changes to collection behavior without user awareness
- Sensor Tower has a documented history (2019 BuzzFeed investigation) of using consumer apps as data collection vehicles for its analytics business
- The extension runs 5+ content scripts on EVERY page, with ad-finder and chatbot-finder running in ALL frames

### Recommendations

1. Users should be clearly informed about the Sensor Tower relationship and the scope of ad/AI data collection
2. Consent should be opt-in (unchecked by default) per GDPR requirements
3. The `uploadWebUsage` remote toggle should not be remotely enableable without explicit user consent
4. AI conversation scraping and chatbot content collection go beyond reasonable functionality for a time tracker and should be disclosed prominently
5. The Pathmatics XHR/fetch hooking should be limited to known ad-serving domains rather than hooking all traffic
