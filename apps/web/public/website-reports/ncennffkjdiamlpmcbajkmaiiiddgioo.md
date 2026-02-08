# Vulnerability Report: 迅雷下载支持 (Xunlei Download Support)

## Metadata
- **Extension ID:** ncennffkjdiamlpmcbajkmaiiiddgioo
- **Name:** 迅雷下载支持 (Xunlei Download Support)
- **Version:** 3.52.14
- **Manifest Version:** 3
- **User Count:** ~55,000,000
- **Analysis Date:** 2026-02-08

## Executive Summary

Xunlei Download Support is the official browser companion extension for Xunlei (Thunder), China's most popular download manager application. The extension intercepts downloads in the browser and redirects them to the native Xunlei desktop application for accelerated downloading. It provides video sniffing (detecting downloadable video on pages), M3U8 stream detection, batch image downloading, cloud storage integration, and screen casting to the desktop app.

The extension requests broad permissions (`<all_urls>`, cookies, webRequest, tabs, downloads, nativeMessaging, scripting) which are **justified by its core download manager functionality**. It needs to intercept HTTP responses to detect downloadable content, access cookies to pass authentication to the download client, and use native messaging to communicate with the installed Xunlei desktop application.

**No malicious behavior, data exfiltration, or key vulnerabilities were identified.** The extension's data collection is limited to usage analytics sent to Xunlei's own statistics server, which is expected for a first-party product of this scale. Cookie access is scoped to passing download authentication to the native client. There is no evidence of proxy infrastructure, extension enumeration/killing, ad injection, market intelligence SDKs, or AI conversation scraping.

## Vulnerability Details

### 1. Cookie Forwarding to Native Application
- **Severity:** LOW
- **Files:** `assets/util-ff1b650c.js`, `assets/background.js-22906370.js`
- **Code:** `chrome.cookies.getAll(E, E => { let B=""; if(E){ for(const C in E) B=B.concat(E[C].name,"=",E[C].value,...) } C(B) })`
- **Verdict:** The extension reads cookies for the URL being downloaded and forwards them to the native Xunlei client via native messaging (`com.thunder.chrome.host`). This is **expected behavior** for a download manager -- it needs authentication cookies to resume/accelerate downloads that originated in an authenticated browser session. Cookies are only read for specific download URLs, not harvested broadly. The data stays local (sent to the native app on the same machine via Chrome's native messaging API).

### 2. Remote Configuration Loading
- **Severity:** LOW
- **Files:** `assets/util-ff1b650c.js`, `assets/background.js-22906370.js`
- **Code:** Fetches `http://static-xl.a.88cdn.com/json/xl_chrome_ext_config.json`
- **Verdict:** The extension loads a remote JSON configuration file that controls video detection domains, blacklisted sites, and feature flags. This is a common pattern for configurable extensions. The config is fetched over HTTP (not HTTPS), which is a minor concern for MITM but the config only controls UI behavior (video tag visibility, domain lists), not code execution. No `eval()` or dynamic script injection from remote config was found.

### 3. Local HTTP Communication with Desktop Client
- **Severity:** LOW
- **Files:** `assets/background.js-22906370.js`
- **Code:** `http://127.0.0.1:5021/getbhoconfig`, `http://127.0.0.1:5021/setbhoconfig`, `http://127.0.0.1:5021/setconfig`
- **Verdict:** The extension communicates with a local HTTP server (port 5021) run by the Xunlei desktop client for BHO (Browser Helper Object) configuration synchronization. This is a legacy integration pattern. Communication is strictly localhost and only transmits configuration preferences, not user data.

### 4. Usage Analytics / Telemetry
- **Severity:** LOW
- **Files:** `assets/stat-e9139785.js`, `assets/background.js-22906370.js`
- **Code:** Reports to `http://stat.download.xunlei.com:8099/` with event IDs, page URLs (for download context), file sizes, and extension version.
- **Verdict:** Standard product telemetry. Event data includes: which pages downloads are triggered from, file sizes, whether Thunder client is installed, feature usage counts. This is **clearly part of intended functionality** for a first-party product analytics system. No PII beyond page URLs is collected. The telemetry endpoint is Xunlei's own infrastructure.

### 5. Content Script Injection on All Pages
- **Severity:** LOW
- **Files:** `assets/content.js-loader-9a2f598c.js`, `assets/content.js-e4490f5d.js`
- **Code:** Content script runs on `http://*/*`, `https://*/*`, `ftp://*/*` at `document_start`
- **Verdict:** The content script provides the video detection overlay (download/save/cast buttons on video elements), the download footer bar, link interception for Thunder-compatible protocols (thunder://, ed2k://, magnet:), multi-select download mode, and HuggingFace/ModelScope model batch downloading. All functionality is directly related to the extension's purpose. No data harvesting, DOM scraping, or injection of ads/tracking was found.

### 6. Risk Check API
- **Severity:** INFO
- **Files:** `assets/background.js-22906370.js`
- **Code:** Sends URLs to `https://api-shoulei-ssl.xunlei.com/xlppc.blacklist.api/v1/risk/check` and `v1/check`
- **Verdict:** The extension sends download URLs and page URLs to Xunlei's risk checking API to verify content safety before enabling download/streaming features. This is a **content safety feature**, not surveillance. The API response controls whether the "fluent play" and video tag features are shown. This is equivalent to Safe Browsing checks.

## False Positive Table

| Pattern | Location | Reason |
|---------|----------|--------|
| `innerHTML` | `background.js-22906370.js` | Used for creating UI prompt dialogs (version upgrade notices, install prompts). Static HTML templates, no user data interpolation. |
| `document.cookie` access | `content.js-e4490f5d.js` | Read only to pass to native download client for authenticated downloads. Not exfiltrated. |
| `chrome.scripting.executeScript` | `background.js-22906370.js` | Used for clipboard copy functionality and toast notification display. Executes fixed functions, not remote code. |
| `chrome.cookies.getAll` | `util-ff1b650c.js` | Scoped to download URLs only. Cookies forwarded to local native messaging host, not external servers. |
| `fetch()` HEAD requests | `background.js-22906370.js` | Used only to get Content-Length headers for file size reporting in analytics. |
| Vue.js `querySelector` | `content.js-e4490f5d.js` | Vue 3 framework DOM operations for UI components. |

## API Endpoints Table

| Endpoint | Method | Purpose | Data Sent |
|----------|--------|---------|-----------|
| `http://stat.download.xunlei.com:8099/` | GET | Usage analytics | Event IDs, page URL, file size, OS, product version, peer ID |
| `http://static-xl.a.88cdn.com/json/xl_chrome_ext_config.json` | GET | Remote config | None (read-only) |
| `https://api-shoulei-ssl.xunlei.com/xlppc.blacklist.api/v1/risk/check` | POST | Content risk check | Download URLs, file names |
| `https://api-shoulei-ssl.xunlei.com/xlppc.blacklist.api/v1/check` | POST | Website blacklist check | Page URL, page title |
| `https://sl-m-ssl.xunlei.com/entry/browser-plugin` | N/A | Recall/promotion entry point | Plugin peer ID (URL param) |
| `http://127.0.0.1:5021/*` | GET/POST | Local desktop client config sync | BHO config key/value pairs |
| `https://down.sandai.net/thunder11/XunLeiWebSetup_ext.exe` | N/A | Thunder installer download | None |
| Native: `com.thunder.chrome.host` | Native Messaging | Download delegation to desktop client | Download URL, cookies, referrer, filename, user agent |

## Data Flow Summary

1. **Download Interception:** Extension monitors `webRequest.onHeadersReceived` for downloadable content. When detected, it extracts URL, referrer, cookies, and file metadata, then forwards to the native Xunlei client via `chrome.runtime.connectNative("com.thunder.chrome.host")`.

2. **Video Detection:** Content script monitors video elements and M3U8 streams on pages. Shows overlay UI for download, cloud save, and screen cast operations. Video URLs are sent to the background script which delegates to the native client.

3. **Cookie Handling:** Cookies are read via `chrome.cookies.getAll()` scoped to the download URL's domain. They are passed to the local native messaging host only -- never to external servers.

4. **Analytics:** Usage events (feature usage, download counts, install status) are reported to `stat.download.xunlei.com` with anonymized telemetry data. This is first-party product analytics.

5. **Risk Checking:** Before enabling video features on a page, the extension checks the URL against Xunlei's risk/blacklist API. This is a safety feature.

6. **AI Model Downloads:** Special integration with HuggingFace, ModelScope, and HF-Mirror to enable batch downloading of AI model files via the Xunlei client.

## Overall Risk: **CLEAN**

This is a legitimate, well-known download manager companion extension from Xunlei (Thunder), one of China's largest software companies. The broad permissions are justified by its core functionality of intercepting and accelerating browser downloads. Cookie access is properly scoped to download URLs and forwarded only to the local native client. Analytics are standard first-party product telemetry. No malicious behavior, data exfiltration, proxy infrastructure, extension enumeration, ad injection, or obfuscation techniques were identified. The codebase is a standard Vite-bundled Vue 3 application with clear, purpose-driven functionality.
