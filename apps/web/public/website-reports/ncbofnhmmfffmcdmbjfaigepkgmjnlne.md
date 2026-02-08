# Vulnerability Report: LearnPlatform for Students

## Metadata
| Field | Value |
|---|---|
| Extension Name | LearnPlatform for Students |
| Extension ID | ncbofnhmmfffmcdmbjfaigepkgmjnlne |
| Version | 1.25 |
| Manifest Version | MV3 |
| Users | ~5,000,000 |
| Minimum Chrome | 88 |

## Permissions
- `alarms` - Scheduling periodic tasks (minute and hour intervals)
- `tabs` - Monitoring active tab URL to match against EdTech domain list
- `storage` - Persisting state (user email, domains, time-on-system data)
- `identity` / `identity.email` - Getting the signed-in Google profile email
- `idle` - Detecting device lock state to pause/resume tracking
- **Host permissions**: `https://app.learnplatform.com/*`, `https://ep.learnplatform.com/*`

## Content Security Policy
```json
"script-src": "'self'",
"object-src": "'self'"
```
Restrictive, no unsafe-eval or unsafe-inline. Good.

## Executive Summary

LearnPlatform for Students is an EdTech engagement tracking extension used by school districts to measure student usage of educational tools. It monitors which tabs the student visits, matches URLs against a downloaded list of known EdTech product domains, tracks time-on-system per tool, and sends aggregated usage data (tool ID, seconds spent, load counts) to LearnPlatform's servers every minute.

The extension is **invasive by design** -- it monitors all tab URLs, identifies the user by email via `chrome.identity`, and transmits usage telemetry. However, this is the **explicitly stated and intended purpose** of the extension: providing school administrators visibility into EdTech product engagement. There are no content scripts, no DOM injection, no XHR/fetch hooking, no dynamic code execution, no extension enumeration, no proxy infrastructure, and no third-party SDKs. All network traffic goes exclusively to LearnPlatform's own servers.

**No malicious behavior or significant vulnerabilities were identified.**

## Vulnerability Details

### INFO-01: URL Monitoring of All Active Tabs
- **Severity**: INFO
- **Files**: `background.js` (function `Ce`, `je`)
- **Description**: The extension monitors `chrome.tabs.onUpdated`, `chrome.tabs.onActivated`, and `chrome.windows.onFocusChanged` to observe every active tab URL. Each URL is matched against a list of known EdTech domains. Only matching tool IDs (not full URLs) and time data are transmitted.
- **Code**: `chrome.tabs.onUpdated.addListener(((e,t,n)=>{"complete"===t.status&&n.active&&Ce(n)}))`
- **Verdict**: Expected behavior for an EdTech usage tracking tool. The URL matching is done locally, and only the tool_id of matched domains is sent to the server, not the raw URL. The URL truncation logic (`xe` function) applies domain-specific truncation rules to limit data sent. This is consistent with the extension's stated purpose.

### INFO-02: User Email Collection via chrome.identity
- **Severity**: INFO
- **Files**: `background.js`
- **Description**: The extension retrieves the user's Google account email using `chrome.identity.getProfileUserInfo` and sends it to `data.learnplatform.com` to resolve a user ID.
- **Code**: `chrome.identity.getProfileUserInfo({accountStatus:"ANY"},(({email:t})=>e(t)))`
- **Verdict**: Required for the extension's purpose of linking usage data to student accounts. Email is sent only to LearnPlatform's own servers.

### INFO-03: Periodic Aggregation Sends Usage Data
- **Severity**: INFO
- **Files**: `background.js` (function `Ue`)
- **Description**: Every minute, the extension sends aggregated usage data to `ep.learnplatform.com/api/aggregations`. Data includes email, user_type, user_id, and session events (tool_id, seconds, load counts).
- **Code**: `fetch(\`${ve().epUrl}/api/aggregations\`,{method:"POST",...body:JSON.stringify(s)})`
- **Verdict**: Core functionality. Data payload is limited to tool engagement metrics, not browsing history.

### INFO-04: new Function("return this") in popup.js
- **Severity**: INFO (False Positive)
- **Files**: `popup.js`
- **Description**: A single `new Function("return this")` call exists in the popup bundle.
- **Verdict**: Standard JavaScript polyfill pattern for obtaining global `this` reference. Not a security concern.

## False Positive Table

| Pattern | Location | Reason |
|---|---|---|
| `new Function("return this")` | popup.js | Standard global-this polyfill |
| `innerHTML` (5 occurrences) | popup.js | React 16 DOM rendering internals (`dangerouslySetInnerHTML` property handling) |
| `clipboardData` | popup.js, options.js | React synthetic event system for clipboard events |
| `getSelection` | popup.js, options.js | React DOM selection management for controlled inputs |
| `Proxy` references | popup.js, options.js | JavaScript built-in object references in utility type-checking code |
| `postMessage` | popup.js | React scheduler using MessageChannel for async work scheduling |
| `encodeURIComponent` | background.js | Standard URL encoding for API request to data service |

## API Endpoints Table

| Endpoint | Method | Purpose | PII Sent |
|---|---|---|---|
| `https://app.learnplatform.com/api/chrome_extension/domains` | HEAD/GET | Download list of tracked EdTech domains | None |
| `https://data.learnplatform.com/public/api/v1/processor/people/{email}` | GET | Resolve user email to user ID | Email |
| `https://data.learnplatform.com/public/api/v1/processor/people/fetch?email=...&user_type=...` | POST | Create/fetch user record (fallback) | Email, user_type |
| `https://ep.learnplatform.com/api/aggregations` | POST | Submit minute-by-minute usage aggregations | Email, user_id, tool engagement data |
| `https://ep.learnplatform.com/api/load_metric` | POST | Submit domain download performance metrics | Email, user_id |

## Data Flow Summary

1. **Startup**: Extension initializes, loads cached state from `chrome.storage.local`, retrieves user email via `chrome.identity.getProfileUserInfo`, resolves email to user_id via LearnPlatform data service.
2. **Domain List**: Downloads a list of EdTech product domains from `app.learnplatform.com` (refreshed hourly). Supports redirect caching (24h TTL).
3. **Tab Monitoring**: On every tab update/activation/window focus change, the active tab URL is matched locally against the domain list using regex. Only matched tool IDs are recorded.
4. **Time Tracking**: For matched tools, time-on-system is tracked in-memory. Paused when window loses focus or device locks.
5. **Aggregation**: Every minute, accumulated tool usage (tool_id + seconds + load counts) is POSTed to `ep.learnplatform.com/api/aggregations`.
6. **No content scripts**: The extension does not inject any scripts into web pages. No DOM manipulation occurs on visited sites.

## Overall Risk Assessment

**CLEAN**

This extension performs EdTech usage monitoring as clearly described in its store listing. While it is privacy-invasive (monitoring all tab URLs, identifying users by email, and transmitting usage data), this is the extension's explicit and intended purpose for school district EdTech analytics. Key mitigating factors:

- **Manifest V3** with restrictive CSP (no unsafe-eval/unsafe-inline)
- **No content scripts** -- zero injection into web pages
- **No broad host permissions** -- only LearnPlatform domains
- **Local URL matching** -- raw URLs are not exfiltrated; only matched tool IDs are sent
- **All traffic goes to first-party servers** (learnplatform.com)
- **No dynamic code execution** (except standard global-this polyfill)
- **No third-party analytics/tracking SDKs**
- **No extension enumeration, proxy behavior, or kill switches**
- **Clean library stack**: React 16, Immer, escape-string-regexp -- all well-known, benign libraries
