# Vulnerability Report: NextAI Translator

## Metadata
- **Extension ID**: ogjibjphoadhljaoicdnjnmgokohngcc
- **Extension Name**: NextAI Translator
- **Version**: 0.6.2
- **Users**: ~100,000
- **Manifest Version**: 3
- **Analysis Date**: 2026-02-15

## Executive Summary

NextAI Translator is a browser extension that provides AI-powered translation services using ChatGPT and other AI APIs. The extension captures user-selected text on web pages and sends it to various AI translation services. While the core translation functionality is legitimate, the extension exhibits concerning behavior by intercepting and extracting API authentication tokens from third-party services (OpenAI, Moonshot, ChatGLM) using the webRequest API. This creates a security risk as the extension can capture sensitive authentication credentials that users provide to these AI services, potentially enabling unauthorized access to user accounts.

The extension collects user text selections from all websites (via content script on `<all_urls>`) and sends this data to multiple external AI providers including MiniMax, OpenAI, Google, Microsoft, Baidu, and others. The webRequest listeners actively monitor and extract Authorization headers and API keys from users' legitimate interactions with AI services, storing these in local storage.

## Vulnerability Details

### 1. MEDIUM: Authentication Token Harvesting via webRequest Interception

**Severity**: MEDIUM
**Files**: assets/src/browser-extension/background/index-380b5a71.js (lines 178-220)
**CWE**: CWE-522 (Insufficiently Protected Credentials)

**Description**: The extension uses webRequest listeners to intercept network requests to OpenAI, Moonshot, and ChatGLM domains and extracts authentication tokens from the request headers and body. These tokens are then stored in local storage.

**Evidence**:
```javascript
// Extracting OpenAI Arkose public_key request data
t.webRequest.onBeforeRequest.addListener(e => {
  if (e.url.includes("/public_key") && !e.url.includes(h)) {
    if (!e.requestBody) return;
    const s = new URLSearchParams;
    for (const r in e.requestBody.formData) s.append(r, e.requestBody.formData[r]);
    t.storage.local.set({
      [y]: e.url,
      [g]: s.toString() || new TextDecoder("utf-8").decode(new Uint8Array(e.requestBody.raw?.[0].bytes))
    }).then(() => {
      console.log("Arkose req url and form saved")
    })
  }
}, {
  urls: ["https://*.openai.com/*"],
  types: ["xmlhttprequest"]
}, ["requestBody"])

// Extracting Moonshot (Kimi) access_token from Authorization header
t.webRequest.onBeforeSendHeaders.addListener(e => {
  if (e.url.includes("/api/user")) {
    const a = ((e.requestHeaders || []).find(o => o.name === "Authorization")?.value || "").split(" ")[1];
    t.storage.local.set({
      [f]: a
    }).then(() => {
      console.log("Kimi access_token saved")
    })
  }
}, {
  urls: ["https://*.moonshot.cn/*"],
  types: ["xmlhttprequest"]
}, ["requestHeaders"])

// Extracting ChatGLM access_token from Authorization header
t.webRequest.onBeforeSendHeaders.addListener(e => {
  if (e.url.includes("/chatglm/user-api/user/info")) {
    const a = ((e.requestHeaders || []).find(o => o.name === "Authorization")?.value || "").split(" ")[1];
    t.storage.local.set({
      [w]: a
    }).then(() => {
      console.log("Kimi access_token saved")
    })
  }
}, {
  urls: ["https://*.chatglm.cn/*"],
  types: ["xmlhttprequest"]
}, ["requestHeaders"])
```

**Verdict**: This behavior allows the extension to capture authentication tokens that users provide to third-party AI services. While the stated purpose appears to be enabling the extension to use these services on behalf of the user, this creates a significant security risk. The tokens are stored in local storage where they could be accessed by malicious scripts or exfiltrated. Users are likely unaware that their API credentials for these services are being captured and stored by the extension. This pattern is concerning even if the current implementation doesn't appear to exfiltrate the tokens to the developer's servers.

### 2. MEDIUM: User Text Selection Collection from All Websites

**Severity**: MEDIUM
**Files**: assets/src/browser-extension/content_script/index-577fd2a8.js (lines 2870-2920), assets/i18n-0b7e0a68.js (line 20225-20260)
**CWE**: CWE-359 (Exposure of Private Personal Information to an Unauthorized Actor)

**Description**: The extension injects a content script on all URLs (`<all_urls>`) that captures user text selections via mouseup, touchend, and keyboard hotkey events. This selected text is then sent to multiple third-party AI translation services.

**Evidence**:
```javascript
// Content script capturing text selection
let u = (window.getSelection()?.toString() ?? "").trim();
if (u)
  if (s.autoTranslate === !0) {
    const f = Yt(a),
      p = Vt(a);
    Zt({
      getBoundingClientRect: () => new DOMRect(f, p, wt, wt)
    }, u)
  }

// Sending to MiniMax API
const o = `https://api.minimax.chat/v1/text/chatcompletion_pro?GroupId=${n.miniMaxGroupID}`,
  a = {
    "Content-Type": "application/json",
    Authorization: `Bearer ${i}`
  },
  s = {
    model: r,
    tokens_to_generate: 1024,
    temperature: .9,
    top_p: .95,
    stream: !0,
    messages: [{
      sender_type: "USER",
      sender_name: "用户",
      text: t.rolePrompt ? t.rolePrompt + `\n\n` + t.commandPrompt : t.commandPrompt
    }]
  };
```

**Verdict**: While text selection capture is expected for a translation extension, the extension has access to potentially sensitive information that users select on any website, including passwords shown on screen, personal messages, financial information, etc. The extension sends this data to multiple third-party services (MiniMax, OpenAI, Google, Microsoft, Baidu, etc.) which creates privacy exposure. However, this is disclosed in the extension's description and is core to its functionality as a translation tool. The risk is moderate because users must actively select text for it to be captured, though auto-translate settings could make this less intentional.

## False Positives Analysis

The ext-analyzer flagged one exfiltration flow: `document.getElementById → fetch(api.minimax.chat)`. This is a legitimate translation flow where user input is sent to the MiniMax translation API. For a translation extension, sending user text to external translation services is expected and disclosed functionality, not unauthorized exfiltration.

The extension is also flagged as "obfuscated" - however, examination of the code shows this is webpack-bundled React code with standard minification, not intentional obfuscation to hide malicious behavior.

## API Endpoints Analysis

| Endpoint | Purpose | Data Sent | Risk |
|----------|---------|-----------|------|
| api.minimax.chat | AI translation service | User-selected text, API key | MEDIUM - Third-party AI service receives user selections |
| openai.com | OpenAI API access | User-selected text, API keys | MEDIUM - Legitimate but captures auth tokens |
| moonshot.cn | Moonshot (Kimi) AI API | User-selected text, API keys | MEDIUM - Legitimate but captures auth tokens |
| chatglm.cn | ChatGLM AI API | User-selected text, API keys | MEDIUM - Legitimate but captures auth tokens |
| deepseek.com | DeepSeek AI API | User-selected text, API keys | MEDIUM - Third-party AI service |
| cohere.ai | Cohere AI API | User-selected text, API keys | MEDIUM - Third-party AI service |
| raw.githubusercontent.com | Configuration updates | None (downloads config) | LOW - Fetches promotion configurations |
| ingest.sentry.io | Error tracking | Error logs | LOW - Standard error monitoring |
| googletagmanager.com | Analytics | Usage metrics | LOW - Standard analytics |
| google-analytics.com | Analytics | Usage metrics | LOW - Standard analytics |
| speech.platform.bing.com | Text-to-speech | Text for speech synthesis | LOW - Disclosed translation feature |
| microsoft.com | Microsoft Translator API | User-selected text | LOW - Disclosed translation service |
| google.com / googleapis.com | Google Translate API | User-selected text | LOW - Disclosed translation service |
| baidu.com | Baidu Translate API | User-selected text | LOW - Disclosed translation service |
| volces.com | Volcengine AI API | User-selected text | LOW - Disclosed translation service |

## Overall Risk Assessment

**RISK LEVEL: MEDIUM**

**Justification**:
The extension provides legitimate translation functionality but exhibits two concerning behaviors that elevate it to MEDIUM risk:

1. **Authentication Token Harvesting**: The extension actively intercepts and extracts API authentication tokens from users' interactions with OpenAI, Moonshot, and ChatGLM services. While this appears intended to enable the extension to use these services, it creates a security risk by capturing and storing sensitive credentials. Users are unlikely to be aware their API keys are being harvested in this manner.

2. **Broad Data Collection**: The extension collects user text selections from all websites and sends this data to multiple third-party Chinese and international AI services, creating privacy exposure. While disclosed as translation functionality, the breadth of services and automatic capture creates meaningful privacy risk.

The extension does not appear to engage in hidden malicious activity, credential theft for unauthorized purposes, or C2 communication. The behaviors are related to its stated translation functionality. However, the authentication token interception pattern is concerning from a security perspective and the broad text selection capture across all websites presents privacy concerns.

The extension would be LOW risk if it only performed translation on user-initiated requests without harvesting API tokens from other services. The token harvesting behavior specifically elevates this to MEDIUM risk due to the security implications of capturing authentication credentials from third-party services.
