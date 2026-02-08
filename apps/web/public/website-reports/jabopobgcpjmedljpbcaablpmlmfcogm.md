# WhatFont - Security Analysis Report

## Metadata
| Field | Value |
|-------|-------|
| **Extension Name** | WhatFont |
| **Extension ID** | jabopobgcpjmedljpbcaablpmlmfcogm |
| **Version** | 3.2.0 |
| **Manifest Version** | 3 |
| **Author** | chengyin.liu@gmail.com |
| **User Count** | ~3,000,000 |
| **Homepage** | http://chengyinliu.com/whatfont.html |

## Executive Summary

WhatFont is a clean, minimal font identification extension built with React and bundled with standard tooling. It uses Manifest V3 with only `activeTab` and `scripting` permissions -- the absolute minimum needed for its stated purpose. The extension has no network communication capabilities (zero `fetch`, `XMLHttpRequest`, or `WebSocket` calls), no dynamic code execution (`eval`, `new Function`), no cookie/storage access, and no data exfiltration pathways. The only external endpoint is a Sentry error monitoring DSN, which is a known false positive. The codebase consists of a browser-polyfill wrapper, React/ReactDOM production bundle, and font detection logic using `getComputedStyle`.

## Permissions Analysis

| Permission | Justification | Risk |
|-----------|---------------|------|
| `activeTab` | Required to access the current tab's DOM for font inspection | LOW - Minimal, user-initiated only |
| `scripting` | Required to inject content script on click | LOW - Standard MV3 pattern |

**CSP**: Default MV3 CSP (no custom overrides). No `unsafe-eval`, no `unsafe-inline`, no remote script sources.

## Vulnerability Details

**No vulnerabilities found.**

The extension has an exceptionally small attack surface:
- No background persistent connections or network calls
- No `content_scripts` auto-injection (injected on-demand via `scripting.executeScript` on user click)
- No access to cookies, storage, bookmarks, history, or any sensitive Chrome APIs
- No `host_permissions` or broad URL patterns
- No web-accessible resources

## False Positive Table

| Pattern | Location | Context | Verdict |
|---------|----------|---------|---------|
| `innerHTML` (9 occurrences) | contentScript/index.js | React/ReactDOM production internals (`dangerouslySetInnerHTML` prop handling, SVG namespace rendering) | **FP - React framework** |
| `cookie` (1 occurrence) | contentScript/index.js | Browser-polyfill API definition table listing `cookies` API methods | **FP - Polyfill metadata** |
| `password` (2 occurrences) | contentScript/index.js | React input type enumeration (`type==="password"`) for controlled components | **FP - React framework** |
| `clipboard` (4 occurrences) | contentScript/index.js | React clipboard event handling (`clipboardData`) | **FP - React framework** |
| `tunnel` (8 occurrences) | contentScript/index.js | Sentry SDK transport tunnel configuration | **FP - Sentry SDK** |
| `inject` (1 occurrence) | contentScript/index.js | React DevTools hook injection (`Is.inject(cw)`) | **FP - React DevTools** |
| `affiliate` (6 occurrences) | contentScript/index.js | Facebook copyright notices ("Facebook, Inc. and its affiliates") | **FP - License text** |
| Sentry SDK (`@sentry`, 41 refs) | contentScript/index.js, background/index.js | Standard error monitoring, Sentry debug IDs | **FP - Sentry SDK** |
| `postMessage` (1 occurrence) | contentScript/index.js | React internal communication | **FP - React framework** |

## API Endpoints Table

| Endpoint | Purpose | Data Sent | Risk |
|----------|---------|-----------|------|
| `https://o4506814553522176.ingest.sentry.io/4506814688657408` | Sentry error monitoring | Crash reports, stack traces | LOW - Standard error monitoring, no PII |

No other external endpoints found. Zero `fetch()`, `XMLHttpRequest`, `sendBeacon`, or `WebSocket` calls exist in the codebase.

## Data Flow Summary

1. **User clicks extension icon** -> `action.onClicked` listener fires in service worker
2. **Service worker** -> Checks tab URL starts with `http`, injects `/contentScript/index.js` via `chrome.scripting.executeScript`
3. **Content script** -> Reads `getComputedStyle` on hovered elements to extract font-family, font-size, font-weight, line-height
4. **Content script** -> Displays font info in an overlay tooltip on the page
5. **Content script** -> Sends `activated`/`deactivated` events to background via `runtime.sendMessage` (title updates only)
6. **Sentry SDK** -> Reports unhandled errors to Sentry (standard error monitoring)

**No data leaves the browser** except Sentry crash reports. No user browsing data, page content, or font usage is transmitted anywhere.

## Overall Risk: **CLEAN**

WhatFont is an exemplary minimal extension. It uses the most restrictive permission set possible (activeTab + scripting), has zero network communication for data collection, contains no obfuscation, no dynamic code execution, no remote configuration, and no tracking. The 2.2MB content script size is entirely attributable to the bundled React/ReactDOM production build and Sentry SDK. The extension does exactly what it advertises -- identifies fonts on web pages -- with no suspicious behavior whatsoever.
