# StayFocusd (laankejkbhbdhmipfmgcngdelahlfoji) - Vulnerability Report

## Executive Summary

StayFocusd v4.4.3 is a website blocking/productivity extension with **4M+ users** that is now owned by **Sensor Tower** (a mobile app intelligence company). While it legitimately blocks distracting websites, it embeds a massive data collection infrastructure that goes far beyond its stated purpose. The extension contains:

1. **Sensor Tower's Pathmatics ad intelligence SDK** (`@sensortower/ad-finder`) -- an XHR/fetch hooking system that intercepts all HTTP responses on every page to scrape ads from YouTube, Hulu, Netflix, TikTok, Twitter/X, and all VAST-compliant ad networks.
2. **A comprehensive browsing data upload pipeline** sending per-site session durations, page view counts, URL query parameters, AI chatbot conversations, and chatbot interaction data to `https://stayfocusd.st-panel-api.com`.
3. **LZ-String compression** of data payloads before upload (the "data_compression_exfil" flags).
4. **Google Analytics (GA4) Measurement Protocol** telemetry with a hardcoded API secret, active in every content script.
5. **Gen-AI prompt/response collection** targeting ChatGPT, Gemini, DeepSeek, Perplexity, and Copilot.
6. **Chatbot interaction scraping** from dozens of customer service chatbot widgets (Intercom, Zendesk, Drift, Salesforce, etc.).

The extension explicitly asks for consent via a ToS acceptance flow, and there is an opt-out mechanism (`canUploadData` / `hasAcceptedToS`). However, the sheer scope and nature of data collection (AI conversations, ad scraping via XHR hooking, URL query parameters) goes significantly beyond what a user would expect from a "website blocker" extension.

**Overall Risk Assessment: MEDIUM-HIGH**

---

## Architecture Overview

| Component | File | Purpose |
|---|---|---|
| Background service worker | `background.js` | Orchestrates uploads, schedules jobs, handles ad-finder messages |
| Ad scraper (injected) | `assets/youtube-hulu-vast-ads.js` | XHR/fetch hook, scrapes ads from YouTube/Hulu/Netflix/TikTok/Twitter |
| Ad finder content script | `content-scripts/ad-finder.js` | Pathmatics SDK host, detects display ads via CSS rule engine |
| Gen-AI collector | `content-scripts/gen-ai-collector.js` | Scrapes ChatGPT/Gemini/DeepSeek/Perplexity/Copilot prompts & responses |
| AI link modifier | `content-scripts/ai-link-modifier.js` | Modifies AI search result links |
| Chatbot finder | `content-scripts/chatbot-finder.js` | Detects and scrapes 30+ chatbot widgets |
| Usage monitor | `content-scripts/usage-monitoring.js` | Tracks time spent per website |
| Overlay | `content-scripts/overlay.js` | Displays blocking overlays |
| Smart bomb | `content-scripts/smart-bomb.js` | Content blocking features |
| Blocked statistics | `content-scripts/blocked-statistics.js` | Dashboard with Vue app; contains full API client |
| Shared SDK | `chunks/_virtual_wxt-plugins-DUYZiXji.js` | Core shared library: API client, LZ-String, ad-finder SDK, Zod schemas |

### Shared Codebase with StayFree

StayFocusd is explicitly part of the **"StayFree Family"** (confirmed in localization strings: "StayFocusd is now part of the StayFree Family"). Both extensions share:
- The same `@sensortower/ad-finder` / Pathmatics SDK
- The same `st-panel-api.com` backend API
- The same WXT framework (Web Extension Tools)
- The same `@wxt-dev/analytics` GA4 integration
- The same remote config system
- References to `FirstSensorTowerInstallDate` storage key

---

## Vulnerability Analysis

### VULN-01: XHR/Fetch Interception for Ad Intelligence Scraping
**Severity: HIGH (CVSS 7.5)** -- AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:N/A:N

**Files:**
- `assets/youtube-hulu-vast-ads.js:697-719` -- XHR.prototype.send monkey-patch + global fetch replacement
- `background.js:5582-5600` -- Pathmatics crawl upload URL and config

**Description:**
The `youtube-hulu-vast-ads.js` script is injected into pages via a `<script>` element (CSP permitting). It hooks `XMLHttpRequest.prototype.send` and replaces `window.fetch` globally. Every successful HTTP response (status 200-210) with content types including text, JSON, XML, or JavaScript has its response body intercepted and passed to ad-detection callbacks. This intercepts ALL network traffic on the page, not just ad-related traffic.

The XHR hook:
```javascript
// youtube-hulu-vast-ads.js:697-706
i = XMLHttpRequest.prototype.send;
function s() {
    let f = this.onreadystatechange, p = arguments;
    this.onreadystatechange = function(m) {
        return r(m, this), f?.apply?.(this, arguments)
    };
    i.apply(this, p);
}
XMLHttpRequest.prototype.send = s;
```

The fetch hook:
```javascript
// youtube-hulu-vast-ads.js:707-719
let u = C.fetch;
let l = function() {
    return u.apply(this, arguments).then(async f => {
        let p = f.headers.get("Content-Type");
        if (p && (p.includes("text") || p.includes("json") || ...)) {
            let m = f.clone(), g = await m.text();
            e(g, null, p.includes("json"), m.url)
        }
        return f
    })
};
C.fetch = l;
```

The extracted ad data (crawls) is uploaded to:
- `https://api-pm.stayfreeapps.com/Ajax0001/IPD` (crawl upload)
- `https://api-pm.stayfreeapps.com/Ajax0001/Config` (external config)

**PoC Scenario:** A user visits their bank's website. Any JSON API responses (account data, transaction lists) would have their response bodies read by the XHR hook. While the ad-detection logic filters for ad-related patterns, the interception itself reads ALL response data first, creating a data exposure risk.

**Mitigating factor:** The script filters responses looking specifically for ad-related patterns (VAST XML, ad_id, promoted content). It does not exfiltrate arbitrary responses. The Pathmatics SDK is a known commercial ad intelligence product (acquired by Sensor Tower).

---

### VULN-02: Gen-AI Conversation Harvesting
**Severity: HIGH (CVSS 7.1)** -- AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:N/A:N

**Files:**
- `content-scripts/gen-ai-collector.js:27936-27956` -- Main entry point
- `chunks/_virtual_wxt-plugins-DUYZiXji.js:31771-32062` -- Platform definitions
- `blocked-statistics.js:12592-12627` -- Upload API endpoints

**Description:**
The `gen-ai-collector` content script runs on ALL URLs (`*://*/*`) and actively scrapes user prompts and AI responses from:

| Platform | Hostname | Data Collected |
|---|---|---|
| ChatGPT | chatgpt.com | Prompts, responses, model name, URLs, summaries |
| Gemini | gemini.google.com | Prompts, responses, status (free/premium) |
| DeepSeek | chat.deepseek.com | Prompts, responses |
| Perplexity | perplexity.ai | Prompts, responses |
| Copilot | copilot.microsoft.com | Prompts, responses |

The config schema (line 27819-27833) defines `finders` for: `prompts`, `responses`, `urls`, `summary`, `modelName`, `loadingSignals`, and user `status` (guest/premium/free).

This data is uploaded via three API endpoints:
```javascript
// blocked-statistics.js:12598 -- AI chat prompts
await e("/v1/ai/analytics", { method: "POST", body: { app_id, install_id, prompts: W.chats } })

// blocked-statistics.js:12610 -- AI-generated links
await e("/v1/ai/links", { method: "POST", body: { app_id, install_id, links: W.links } })

// blocked-statistics.js:12622 -- AI interactions
await e("/v1/ai/interactions", { method: "POST", body: { app_id, install_id, interactions: W.interactions } })
```

The gen-ai-collector has a `forbiddenPromptWords` config to filter out sensitive prompts, but this is server-controlled and can be changed remotely.

**PoC Scenario:** A user asks ChatGPT about a sensitive medical condition or proprietary business strategy. The extension scrapes the prompt text, the AI response, and the model name, then uploads it to Sensor Tower's servers tied to the user's persistent install_id.

---

### VULN-03: Chatbot Conversation Scraping
**Severity: MEDIUM (CVSS 5.7)** -- AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:N/A:N

**Files:**
- `content-scripts/chatbot-finder.js` -- Runs on ALL URLs
- `chunks/_virtual_wxt-plugins-DUYZiXji.js:32216-32616` -- Chatbot selector definitions
- `blocked-statistics.js:12628-12658` -- Upload endpoints

**Description:**
The `chatbot-finder` content script detects and scrapes conversations from 30+ customer service chatbot widgets including:
- Intercom, Zendesk, Drift, Salesforce, HubSpot, LiveChat, Crisp, Tidio, Freshchat, Gladly, and many more

It uses CSS selectors to find `userMessageSelector` elements and extracts the text content. Data uploaded via:
```javascript
// blocked-statistics.js:12638 -- Chatbot detection
await e("/v1/ai/chatbot", { method: "POST", body: { install_id, app_id, chatbot_service, hostname, path, timestamp, time_zone } })

// blocked-statistics.js:12654 -- Chatbot chat content
await e("/v1/ai/chatbot_chats", { method: "POST", body: { install_id, app_id, country_code, chatbot_service, hostname, path, chats } })
```

**PoC Scenario:** A user contacts their bank's support chatbot and shares account details. The extension scrapes the conversation and uploads it.

---

### VULN-04: Comprehensive Browsing History & Session Upload
**Severity: MEDIUM (CVSS 5.3)** -- AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:N/A:N

**Files:**
- `background.js:5526-5580` -- Session monitor and usage uploader setup
- `blocked-statistics.js:12347-12416` -- uploadSessions and uploadPageViews
- `content-scripts/usage-monitoring.js` -- Active tab tracking

**Description:**
The extension tracks per-website session durations and page view counts, uploading them to:
```javascript
// blocked-statistics.js:12376
await e("/v1/web/upload", { method: "POST", body: {
    app_id, install_id, time_zone, device_name, device_type,
    birth_year, websites, diff_private_websites
}})

// blocked-statistics.js:12411
await e("/v1/page_views/upload", { method: "POST", body: {
    app_id, install_id, time_zone, device_name, device_type,
    birth_year, websites, diff_private_websites
}})
```

The upload includes `birth_year` (demographic data), `device_type`, `device_name` (browser), and `time_zone`. There is a `diff_private_websites` field suggesting some differential privacy mechanism, but both the raw `websites` and `diff_private_websites` are sent in the same payload, negating the privacy benefit.

---

### VULN-05: URL Query Parameter Harvesting
**Severity: MEDIUM (CVSS 5.3)** -- AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:N/A:N

**Files:**
- `background.js:5755-5817` -- Query parameter collector setup
- `blocked-statistics.js:12660-12672` -- Upload endpoint

**Description:**
The extension uses `webNavigation.onCompleted` to capture URL query parameters from every navigation:
```javascript
// background.js:5778
const k = Object.fromEntries(m.searchParams.entries());
const N = Object.entries(k).map(([W, Tt]) => ({
    name: W, value: Rs(Tt), timestamp: w
}));
```

These are batched and uploaded via:
```javascript
await e("/v1/query_params/upload", { method: "POST", body: {
    app_id, install_id, time_zone, country_code, websites: {
        [hostname]: { [path]: { query_params: [...] } }
    }
}})
```

**PoC Scenario:** A user searches Google. The search query appears in `?q=...`. The extension captures every query parameter name and value, including search terms, UTM tracking codes, session tokens in URLs, and any other URL parameters.

---

### VULN-06: Hardcoded GA4 API Secret + Measurement ID
**Severity: LOW (CVSS 3.1)** -- AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N

**Files:**
- `content-scripts/gen-ai-collector.js:28288-28289`
- `content-scripts/chatbot-finder.js:27458-27460`
- `content-scripts/ai-link-modifier.js:27191-27193`
- `chunks/_virtual_wxt-plugins-DUYZiXji.js:36961-36963`
- (All content scripts share the same credentials)

**Description:**
Every content script contains the same hardcoded Google Analytics 4 credentials:
```javascript
measurementId: "G-RD9W7TJ9TZ",
apiSecret: "XaR9YDEpQc6GG_m2eeA5Jw"
```

This sends events directly to `https://www.google-analytics.com/mp/collect`. While GA4 Measurement Protocol secrets are not considered highly sensitive, they allow anyone to inject fake analytics events into the extension's GA4 property.

---

### VULN-07: Server-Controlled Remote Configuration
**Severity: MEDIUM (CVSS 5.0)** -- AV:N/AC:H/PR:N/UI:R/S:U/C:H/I:N/A:N

**Files:**
- `background.js:5646-5657` -- Remote config fetch job
- `gen-ai-collector.js:27893-27927` -- Config system with remote URLs
- `chunks/_virtual_wxt-plugins-DUYZiXji.js:30085` -- Pathmatics external config

**Description:**
The extension periodically fetches remote configuration that controls:
- Which websites to scrape ads from (`AdRules`, `SiteConfigs`, `UrlBlackList`)
- AI platform definitions (which chatbots to scrape)
- Chatbot CSS selectors
- `forbiddenPromptWords` (what NOT to collect from AI chats)
- Upload intervals and feature flags
- `uploadWebUsage` toggle

This means Sensor Tower can remotely expand or modify what data is collected without a CWS update.

---

## False Positive Analysis

| Triage Flag | Category | Count | Verdict | Explanation |
|---|---|---|---|---|
| T1 | xhr_hook | 11 | **TRUE POSITIVE** | `XMLHttpRequest.prototype.send` monkey-patch + `fetch` replacement in `youtube-hulu-vast-ads.js` and bundled copies in 8 content scripts. All instances are the Pathmatics ad-finder SDK intercepting HTTP responses. |
| T1 | data_compression_exfil | 10 | **TRUE POSITIVE (partial)** | LZ-String library (`compressToBase64`, `compressToUTF16`, `compressToUint8Array`) is used for compressing ad rule parse trees received from config AND for compressing crawl data before upload. The btoa() calls are SparkMD5 hashing ad content for deduplication. |
| V1 | fetch_calls | ~20 | **MIXED** | Many fetch calls are the `ofetch` library (legitimate HTTP client for API calls). Some are GA4 Measurement Protocol uploads. The ad-finder fetch hook is the true concern. |
| V1 | indexedDB_open | ~7 | **FALSE POSITIVE** | Standard WXT framework storage via `idb-keyval` for local data persistence. |
| V2 | document_write | ~7 | **FALSE POSITIVE** | DOMPurify library sanitization patterns (`document.implementation.createHTMLDocument("").open()`). |
| V2 | postMessage | ~10 | **TRUE POSITIVE (benign)** | Used by the Pathmatics SDK for communication between the injected ad-finder script and the content script via `window.postMessage`. Also used by WXT content script invalidation system. Not exfiltration. |
| V1 | base64_encoding | ~10 | **TRUE POSITIVE** | SparkMD5 hashing + btoa() for ad fingerprinting. Also used in GA4 source map injection (CSS loader). |

---

## Data Flow Summary

```
User's Browser
    |
    v
[content-scripts/*] -- XHR/fetch hooks intercept page traffic
    |                -- DOM scrapers find ads, AI prompts, chatbot messages
    |                -- Usage monitoring tracks time per site
    v
[background.js] -- Aggregates data, runs upload schedules
    |
    +---> https://stayfocusd.st-panel-api.com/v1/web/upload (browsing sessions)
    +---> https://stayfocusd.st-panel-api.com/v1/page_views/upload (page views)
    +---> https://stayfocusd.st-panel-api.com/v1/query_params/upload (URL params)
    +---> https://stayfocusd.st-panel-api.com/v1/ai/analytics (AI chat prompts)
    +---> https://stayfocusd.st-panel-api.com/v1/ai/links (AI-generated links)
    +---> https://stayfocusd.st-panel-api.com/v1/ai/interactions (AI interactions)
    +---> https://stayfocusd.st-panel-api.com/v1/ai/chatbot (chatbot detection)
    +---> https://stayfocusd.st-panel-api.com/v1/ai/chatbot_chats (chatbot chats)
    +---> https://stayfocusd.st-panel-api.com/v1/desktop/retail/* (retail ad data)
    +---> https://api-pm.stayfreeapps.com/Ajax0001/IPD (Pathmatics ad crawls)
    +---> https://api-pm.stayfreeapps.com/Ajax0001/Config (Pathmatics config)
    +---> https://www.google-analytics.com/mp/collect (GA4 events)
```

---

## Consent & Opt-Out Mechanism

The extension implements a consent system:
- `hasAcceptedToS()` -- checks if user accepted Terms of Service (links to `sensortower.com/panel-terms`)
- `canUploadData()` -- requires ToS acceptance AND `uploadWebUsage` remote config flag
- Opt-out available at `/v1/analytics/optout` endpoint
- Localized strings: "I allow StayFocusd to collect the data described in our [privacy policy]"
- On update, if user hasn't opted in, it calls `optOut({ installId, optOut: true })`

This is a meaningful consent mechanism, but the scope of collection (AI conversations, ad scraping, chatbot messages) is extreme for a website blocker.

---

## Overall Risk Assessment: **MEDIUM-HIGH**

**Justification:**
- The extension is NOT malware in the traditional sense -- it is a legitimate product owned by Sensor Tower (a major app intelligence company) with disclosed data collection and an opt-in/opt-out mechanism.
- However, the data collection scope is disproportionate to the extension's stated purpose (website blocking). The XHR/fetch hooking, AI conversation scraping, chatbot message harvesting, and URL query parameter collection are all market research/ad intelligence features that users would not reasonably expect from a productivity extension.
- The `@sensortower/ad-finder` Pathmatics SDK converts every user into an unwitting ad intelligence sensor.
- The remote config system means Sensor Tower can expand collection scope without CWS review.
- The shared infrastructure with StayFree confirms this is a systematic data collection operation across multiple extensions.

**Comparison with StayFree (elfaihghhjjoknimpccccmkioofjjfkf):** As suspected, StayFocusd and StayFree share an identical codebase/SDK. The flag profiles are nearly identical because they bundle the same Sensor Tower Pathmatics SDK, the same WXT analytics framework, the same API client, and the same gen-AI/chatbot collection infrastructure. StayFocusd was originally an independent extension and was acquired by the StayFree/Sensor Tower ecosystem.
