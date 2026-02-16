# Security Analysis: SellerSprite - Amazon Research Tool

## Extension Metadata
- **Extension ID**: lnbmbgocenenhhhdojdielgnmeflbnfb
- **Name**: SellerSprite - Amazon Research Tool
- **Version**: 5.0.1
- **Users**: ~400,000
- **Manifest Version**: 3
- **Developer**: SellerSprite (www.sellersprite.com)

## Executive Summary

SellerSprite is a legitimate Amazon seller research tool with extensive permissions for its stated functionality. The extension performs **TikTok data harvesting** via fetch hooking, **AI platform prompt injection** across 6 AI platforms (ChatGPT, Claude, Gemini, DeepSeek, Grok, Doubao), and **Amazon seller data collection**. While these features appear aligned with the tool's marketing/research purpose, they involve intrusive techniques that raise privacy concerns.

**Overall Risk: MEDIUM**

The extension is functionally legitimate but employs aggressive data collection methods typical of market intelligence tools. No evidence of malicious credential theft, extension killing, or unauthorized exfiltration was found. However, the TikTok fetch hooking and AI prompt injection represent significant privacy implications for users.

## Vulnerability Analysis

### 1. TikTok Data Harvesting via Fetch Hooking

**Severity**: MEDIUM-HIGH
**Files**:
- `/assets/inject.ts-D8TEADfP.js` (injected into MAIN world on TikTok)
- `/assets/content.ts-DdLUmAzP.js` (content script listener)

**Description**:
The extension injects code into TikTok's MAIN world context and hooks `window.fetch` to intercept all TikTok API responses. This is for the "KolSprite" feature (influencer/creator marketing analysis).

**Evidence**:
```javascript
// inject.ts-D8TEADfP.js, line 1-15
window.__kol_captureList = {
  "/api/recommend/item_list/": "foryouVideoList",
  "/api/post/item_list": "userVideoList",
  "/api/repost/item_list": "userRepostList",
  "/api/favorite/item_list": "userLikeList",
  "/api/collection/item_list": "userFavoriteList",
  "/api/search/general/full": "searchGeneralList",
  "/api/search/item/full/": "searchVideoList",
  "/api/explore/item_list/": "exploreVideoList",
  "/api/challenge/item_list/": "tagVideoList",
  "/api/following/item_list/": "followingVideoList",
  "/api/friends/item_list/": "friendsVideoList",
  "/api/item/detail": "userVideoDetail",
  "/api/shop": "shopList"
};

function m() {
  const d = window.fetch;
  window.fetch = async function(...t) {
    const [e] = t;
    if (t[0]?.credentials === "omit") return d(e);

    const p = d(e);
    const n = Object.keys(window.__kol_captureList).find(s => i?.includes(s));

    if (n) {
      const s = await p;
      const l = await s.clone().json();
      // Dispatch as CustomEvent for content script to capture
      const w = new CustomEvent(window.__kol_captureList[n], {
        detail: l
      });
      window.dispatchEvent(w);
    }
    return p;
  }
}
```

**Data Captured**:
- TikTok For You feed video lists
- User profiles, posts, reposts, likes, favorites
- Search results (videos and general)
- Shop/product data
- Following/followers lists
- Challenge/tag video lists

**Exfiltration**:
Data is captured via CustomEvents and processed by content scripts. Appears to be used for influencer marketing analysis (KolSprite feature). No direct evidence of unauthorized upload, but processed data is likely sent to `kolsprite.com` APIs for analysis.

**Verdict**: **SUSPICIOUS** - Legitimate use case for influencer marketing tool, but fetch hooking on TikTok is highly intrusive. Users should be explicitly informed.

---

### 2. AI Platform Prompt Injection

**Severity**: MEDIUM
**Files**: `/assets/content.ts-DdLUmAzP.js`

**Description**:
The extension automatically injects user prompts into 6 AI chat platforms when storage contains an `AIPrompt` value. This allows the SellerSprite web app to trigger AI queries via the extension.

**Platforms Targeted**:
1. **ChatGPT** (chatgpt.com) - `#prompt-textarea p` innerHTML injection + button click
2. **Claude** (claude.ai) - `div[contenteditable="true"]` innerHTML injection + send button
3. **Gemini** (gemini.google.com) - `.ql-editor` innerText + Enter keypress
4. **DeepSeek** (chat.deepseek.com) - `textarea` value override + Enter keypress
5. **Grok** (grok.com) - `form textarea` value override + Enter keypress
6. **Doubao** (doubao.com) - `.semi-input-textarea` value override + submit button

**Evidence**:
```javascript
// ChatGPT injection (line 235-244)
function me() {
  u.storage.local.get().then(o => {
    const e = o.AIPrompt;
    e && h("#prompt-textarea p").then(() => {
      document.querySelector("#prompt-textarea p").innerHTML = e;
      h("#composer-submit-button").then(() => {
        document.querySelector("#composer-submit-button").click();
        u.storage.local.remove("AIPrompt");
      })
    })
  })
}

// Claude injection (line 328-337)
function he() {
  u.storage.local.get().then(o => {
    const e = o.AIPrompt;
    e && h('div[contenteditable="true"]').then(() => {
      document.querySelector('div[contenteditable="true"]').innerHTML = e;
      h('button[aria-label="Send message"]').then(() => {
        document.querySelector('button[aria-label="Send message"]').click();
        u.storage.local.remove("AIPrompt");
      })
    })
  })
}
```

**Attack Surface**:
- Prompts are set via `chrome.storage.local` (presumably from background script or web app)
- Direct DOM manipulation (`innerHTML`, `innerText`, `value` property descriptor override)
- Automatic form submission
- Bypasses native input validation by using property descriptors and synthetic events

**Verdict**: **MEDIUM RISK** - Legitimate feature for AI-assisted product research, but allows web app to control AI chat sessions. No evidence of prompt theft (reading responses), only injection.

---

### 3. Amazon Seller Data Collection

**Severity**: LOW
**Files**: `/background/index.js`, `/content/index.js`

**Description**:
The extension's core functionality involves scraping Amazon product data, seller central order data, and integrating with third-party services.

**Permissions Used**:
- `cookies` - Reading Amazon session cookies for authenticated API calls
- `tabs` - Accessing Amazon page URLs and tab data
- `storage` - Persisting user settings and cached data
- `declarativeNetRequest` - Modifying request headers for API access

**Data Sources**:
1. **Amazon Product Pages** - ASINs, pricing, reviews, images, product details
2. **Amazon Seller Central** - Order data (requires seller account)
3. **Alibaba/1688.com** - Sourcing data via image search upload
4. **Google Trends** - Keyword trend data
5. **TrustWerty API** - Product rating verification (`trustwerty.com/api/bulk-asins`)

**Network Request Header Modification**:
```json
// rules/rule-trustwerty.json
{
  "action": {
    "type": "modifyHeaders",
    "requestHeaders": [
      {"header": "origin", "operation": "set", "value": "https://trustwerty.com"},
      {"header": "referer", "operation": "set", "value": "https://trustwerty.com"}
    ]
  },
  "condition": {
    "urlFilter": "trustwerty.com/api/bulk-asins"
  }
}
```

This spoofs origin/referer to access third-party APIs (TrustWerty, KolSprite, TikSave).

**Verdict**: **ACCEPTABLE** - Standard functionality for Amazon research tool. Header modification is for legitimate API access, not CSRF attacks.

---

### 4. OAuth2 and Identity Integration

**Severity**: LOW
**Files**: `/background/index.js`

**Description**:
The extension uses Google OAuth2 for user authentication and launches web auth flows for Facebook/Google login.

**Evidence**:
```javascript
// manifest.json, line 309-314
"oauth2": {
  "client_id": "84356059972-fhtdt93mipsffeil57c9dcoqf3af3996.apps.googleusercontent.com",
  "scopes": [
    "https://accounts.google.com/o/oauth2/v2/auth"
  ]
}

// background/index.js - Facebook OAuth
globalThis.$browser.identity.launchWebAuthFlow({
  url: `https://www.facebook.com/dialog/oauth?${new URLSearchParams({
    display: "popup",
    client_id: "825127318375699",
    redirect_uri: e,
    response_type: "token",
    state: random(14,20).toString(),
    scope: "email"
  })}`,
  interactive: true
})
```

**Verdict**: **ACCEPTABLE** - Standard OAuth implementation for user authentication with SellerSprite services.

---

### 5. Cookie Access for Amazon Sessions

**Severity**: LOW
**Files**: `/background/index.js`

**Description**:
The extension uses `chrome.cookies` API to read/write Amazon session cookies for authenticated seller central access.

**Evidence**:
```javascript
// background/index.js, line 48914-48941
static async get(e) {
  return globalThis.$browser.cookies.get(e);
}

static async set(e) {
  return await globalThis.$browser.cookies.set(e);
}

// Used for Amazon API calls with Cookie header
Cookie: this.cookie(sessionData)
```

**Verdict**: **ACCEPTABLE** - Necessary for accessing Amazon Seller Central APIs with user's authenticated session. Standard practice for Amazon tools.

---

## False Positives

| Pattern | File | Reason |
|---------|------|--------|
| `eval()`, `Function()` | `chunks/chunk-*.js`, `exceljs.min.js` | **FP**: Part of bundled libraries (Vue, Element Plus, ExcelJS) - legitimate dynamic code execution for framework reactivity and Excel parsing |
| `fromCharCode`, `base64` | `background/index.js` | **FP**: Data encoding utilities in libraries (crypto-js for hashing, image processing) |
| `fetch` hooking | `inject.ts-D8TEADfP.js` | **REAL**: TikTok data harvesting (covered in findings) |
| `innerHTML` manipulation | `content.ts-DdLUmAzP.js` | **REAL**: AI prompt injection (covered in findings) |
| `localStorage.getItem` | `chunks/chunk-vxe-table.js` | **FP**: VXE Table library persisting grid state locally |
| `sessionStorage` | `background/index.js` | **FP**: Dexie.js IndexedDB library polyfill check |
| `password` input type | `chunks/chunk-vxe-table.js` | **FP**: VXE Table form component supporting password field types |

---

## API Endpoints & Data Flow

| Service | Endpoint | Purpose | Data Sent |
|---------|----------|---------|-----------|
| **SellerSprite** | `www.sellersprite.com/*` | Core research platform | Amazon ASINs, keywords, user auth tokens |
| **KolSprite** | `www.kolsprite.com/v1/plugin/*` | TikTok influencer data | Video IDs, creator IDs, collected TikTok feed data |
| **KolSprite CDN** | `o.kolsprite.com/caption/*` | TikTok caption/audio transcription | Audio files (up to 10MB), video metadata |
| **TrustWerty** | `trustwerty.com/api/bulk-asins` | Amazon review verification | ASINs |
| **VOC.AI** | `apps.voc.ai/*` | Voice of Customer analysis (partner) | Unknown (separate integration) |
| **Aya3D** | `www.aya3d.com/*` | 3D product visualization (partner) | Unknown (separate integration) |
| **Google Translate** | `translate.googleapis.com/*` | Product translation | Product text |
| **Microsoft Translator** | `api.cognitive.microsofttranslator.com/*` | Product translation | Product text |
| **Alibaba/1688** | Upload to `stream-upload.taobao.com` | Image search for sourcing | Product images |
| **TikSave** | `tiksave.io/api/ajaxSearch` | TikTok video download | Video URLs |

**Token Signature**:
All SellerSprite API calls include a custom `sellersprite_token()` signature (likely HMAC) for authentication:
```javascript
tk: dh.sellersprite_token(endpoint, userData)
```

---

## Data Flow Summary

1. **Amazon → Extension → SellerSprite**: Product data, seller central orders, pricing, reviews
2. **TikTok → Extension → KolSprite**: User feeds, video metadata, creator profiles, shop data (via fetch hook)
3. **AI Platforms ← Extension**: Injected prompts from SellerSprite web app (no response theft detected)
4. **Extension → Third-party APIs**: TrustWerty ratings, Google Translate, Microsoft Translator, Alibaba image search
5. **User Auth**: Google OAuth2, Facebook OAuth for SellerSprite account login

---

## Privacy Concerns

1. **TikTok Fetch Hooking**: Users browsing TikTok have ALL API responses intercepted, including feeds, profiles, and shopping data. This is disclosed in manifest host permissions but not transparently explained.

2. **AI Prompt Injection**: The extension can inject arbitrary prompts into 6 AI platforms. While no response theft occurs, this allows the SellerSprite web app to trigger AI queries without explicit user confirmation per query.

3. **Amazon Cookie Access**: Full access to Amazon session cookies enables seller central data extraction. This is legitimate for the tool but requires user trust.

4. **Third-party Data Sharing**: TikTok data is sent to KolSprite (same developer family), Amazon data to TrustWerty (partner), images to Alibaba. Users should understand data flows to third parties.

---

## Security Posture

**Strengths**:
- No extension enumeration or killing behavior
- No remote config kill switches detected
- No hardcoded credentials or API keys (uses OAuth)
- No residential proxy infrastructure
- No ad injection or search manipulation
- Manifest V3 compliance with proper CSP

**Weaknesses**:
- Fetch hooking in MAIN world (bypass isolation)
- AI prompt injection across multiple platforms
- Extensive host permissions (TikTok, AI platforms, Amazon, Alibaba, etc.)
- Third-party data sharing not fully transparent

---

## Comparison to Malicious Extensions

Unlike StayFree/StayFocusd (Sensor Tower), SellerSprite:
- ✅ Does NOT hook fetch on all sites (only TikTok for KolSprite feature)
- ✅ Does NOT scrape AI conversation responses
- ✅ Does NOT have remote config for silent expansion
- ✅ Does NOT masquerade as a different tool type (clearly marketed as Amazon + TikTok research)

---

## Overall Risk Assessment: **MEDIUM**

**Justification**:
SellerSprite is a **legitimate market intelligence tool** with intrusive but functionally aligned capabilities. The TikTok fetch hooking and AI prompt injection are significant privacy concerns but serve the extension's stated purpose (influencer marketing + product research). No evidence of credential theft, malicious exfiltration, or deceptive behavior.

**Recommendation**:
Users should be aware of:
1. TikTok browsing data is collected when the extension is active
2. The extension can inject prompts into AI chat platforms
3. Amazon session cookies and seller data are accessed
4. Data is shared with SellerSprite, KolSprite, TrustWerty, and other partners

For sellers/marketers using the tool for its intended purpose, the risk is acceptable. For general users who installed it accidentally, the TikTok/AI access is overly broad.

---

## Technical Indicators

- **Obfuscation Level**: Low (standard webpack bundling)
- **Dynamic Code Execution**: Present in libraries (Vue, ExcelJS) - legitimate
- **Network Exfiltration**: To developer-owned domains (sellersprite.com, kolsprite.com) and partners
- **Persistent Storage**: chrome.storage.local, IndexedDB (Dexie.js)
- **Content Script Injection**: document_start (preload.js), document_end (index.js)
- **MAIN World Injection**: TikTok only (inject.ts-D8TEADfP.js)

---

**Analysis Date**: 2026-02-06
**Analyst**: Claude Opus 4.6 (Security Research)
