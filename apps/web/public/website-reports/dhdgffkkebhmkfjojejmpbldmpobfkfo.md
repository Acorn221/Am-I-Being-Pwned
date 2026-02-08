# Vulnerability Report: Tampermonkey

## Metadata
- **Extension Name:** Tampermonkey
- **Extension ID:** dhdgffkkebhmkfjojejmpbldmpobfkfo
- **Version:** 5.4.1
- **Manifest Version:** 3
- **User Count:** ~11,000,000
- **Analysis Date:** 2026-02-08
- **Source Directory:** deobfuscated/

## Executive Summary

Tampermonkey is the most popular userscript manager for Chrome, with ~11 million users. By design, it requires extremely broad permissions (`<all_urls>`, `webRequest`, `webRequestBlocking`, `cookies`, `scripting`, `userScripts`, `declarativeNetRequestWithHostAccess`, `tabs`, `unlimitedStorage`, `clipboardWrite`) because its core functionality is to inject and execute arbitrary user-supplied JavaScript on any webpage.

The extension is **heavily minified but not obfuscated** -- all code follows standard webpack/bundler patterns. The codebase is large (~1.7MB of JS) but corresponds to the expected feature set: userscript injection engine, script editor with ESLint, cloud sync (Google Drive, Dropbox, OneDrive, Yandex), and a Matomo-based anonymous telemetry system.

No malicious behavior, data exfiltration, residential proxy infrastructure, market intelligence SDKs, or unauthorized data harvesting was identified. All network communication serves the extension's documented functionality.

## Vulnerability Details

### 1. Matomo Analytics Telemetry (LOW)
- **Severity:** LOW
- **Files:** `offscreen.js` (lines 69-77), `background.js`, `extension.js`
- **Code:** `de="https://a.tampermonkey.net/matomo.php"` with multiple site IDs and sampling rates
- **Description:** The extension sends anonymous usage telemetry to `a.tampermonkey.net/matomo.php` using a self-hosted Matomo instance. Data includes page title, resolution, random visitor UUID, and visit timestamps. Telemetry is sampled (1-50% depending on distribution channel) and uses standard Matomo pageview/event/ping tracking. Error reports (CSP violations, JS errors) are also sent.
- **Verdict:** **Expected behavior** for a widely-used extension. The data collected is standard anonymous analytics (no PII, no browsing history, no page content). This is transparent and well-known behavior for Tampermonkey.

### 2. Script Blacklist via Remote Server (LOW)
- **Severity:** LOW
- **Files:** `background.js`
- **Code:** `_c="https://blacklist.tampermonkey.net/get.php"`
- **Description:** Tampermonkey maintains a remote blacklist of known malicious userscripts at `blacklist.tampermonkey.net`. When scripts are installed, their metadata is checked against this blacklist. This is a security feature designed to protect users from malicious userscripts.
- **Verdict:** **Beneficial security feature.** The blacklist is a protective mechanism, not a data exfiltration channel.

### 3. Eval Usage for Userscript Compilation (LOW)
- **Severity:** LOW
- **Files:** `background.js`, `content.js`
- **Code:** `eval(c.code)` (Babel ES2015/ES2016 compilation), `eval(compiled)` (CoffeeScript compilation)
- **Description:** `eval()` is used in the context of compiling user-supplied scripts written in CoffeeScript or requiring Babel transpilation. This is core functionality for a userscript manager.
- **Verdict:** **Expected behavior.** A userscript manager's entire purpose is to execute user-supplied code. The eval usage is specifically for transpilation of user-authored scripts.

### 4. Extensive Permission Set (INFO)
- **Severity:** INFO
- **Files:** `manifest.json`
- **Permissions:** `<all_urls>`, `webRequest`, `webRequestBlocking`, `cookies`, `scripting`, `userScripts`, `declarativeNetRequestWithHostAccess`, `tabs`, `unlimitedStorage`, `clipboardWrite`, `notifications`, `webNavigation`, `storage`, `contextMenus`, `alarms`, `offscreen`
- **Description:** The permission set is very broad but each permission maps directly to documented Tampermonkey features: `<all_urls>` + `scripting` + `userScripts` (script injection on any page), `webRequest`/`webRequestBlocking`/`declarativeNetRequestWithHostAccess` (GM_webRequest API), `cookies` (GM_cookie API), `tabs` (GM_openInTab, tab management), `clipboardWrite` (GM_setClipboard), `unlimitedStorage` (large script libraries), `notifications` (GM_notification).
- **Verdict:** **All permissions justified** by the extension's feature set as a userscript manager.

### 5. External Connectability (INFO)
- **Severity:** INFO
- **Files:** `background.js`
- **Description:** The extension supports `externally_connectable` patterns, allowing whitelisted external websites to communicate with the extension. This enables features like one-click userscript installation from greasyfork.org, openuserjs.org, sleazyfork.org, and similar script repositories.
- **Verdict:** **Expected behavior** for userscript installation from trusted repositories.

### 6. Cloud Sync OAuth Integrations (INFO)
- **Severity:** INFO
- **Files:** `background.js`, `extension.js`
- **Endpoints:** Google Drive (`googleapis.com`), Dropbox (`dropboxapi.com`), OneDrive (`api.onedrive.com`), Yandex Disk (`cloud-api.yandex.net`, `webdav.yandex.ru`), Tampermonkey Cloud (`accounts.tampermonkey.net`)
- **Description:** Cloud sync allows users to synchronize their userscript libraries across devices. OAuth2 flows are used for authentication with standard cloud providers.
- **Verdict:** **User-initiated feature** requiring explicit opt-in and OAuth authorization.

## False Positive Table

| Pattern | Location | Reason |
|---------|----------|--------|
| `eval()` usage | background.js | CoffeeScript/Babel transpilation of user scripts |
| `cookie` references | background.js, offscreen.js, page.js | GM_cookie API implementation for userscripts |
| `inject` references | background.js, content.js | Core userscript injection engine |
| `blacklist`/`whitelist` references | background.js, extension.js | Script safety blacklist + URL match whitelist for script execution |
| `proxy` references | content.js, page.js | JavaScript Proxy objects used in sandbox implementation for script isolation |
| `unsafeWindow` references | page.js, content.js | GM_unsafeWindow API -- standard Greasemonkey/Tampermonkey API for userscripts |
| `XMLHttpRequest` implementation | offscreen.js | Custom XHR implementation for GM_xmlhttpRequest cross-origin requests |
| `Matomo` analytics | offscreen.js, background.js, extension.js | Self-hosted anonymous telemetry, standard for large extensions |
| `localStorage` access | offscreen.js, background.js | Visitor UUID persistence for analytics; script storage |
| `management.getAll` / `isAllowedFileSchemeAccess` | background.js, extension.js | Checking extension's own permissions, not enumerating other extensions |

## API Endpoints Table

| Endpoint | Purpose | Data Sent |
|----------|---------|-----------|
| `https://a.tampermonkey.net/matomo.php` | Anonymous telemetry (Matomo) | Page title, screen resolution, random visitor UUID, timestamps |
| `https://blacklist.tampermonkey.net/get.php` | Script safety blacklist | Script metadata for blacklist check |
| `https://accounts.tampermonkey.net/e/oauth2/v1` | Tampermonkey cloud auth | OAuth tokens for cloud sync |
| `https://www.googleapis.com/drive/v3/files` | Google Drive sync | Userscript data (user-initiated) |
| `https://api.dropboxapi.com/2/files/*` | Dropbox sync | Userscript data (user-initiated) |
| `https://api.onedrive.com/v1.0/drive/*` | OneDrive sync | Userscript data (user-initiated) |
| `https://cloud-api.yandex.net/v1/disk/*` | Yandex Disk sync | Userscript data (user-initiated) |
| `https://webdav.yandex.ru` | Yandex WebDAV sync | Userscript data (user-initiated) |
| `https://www.tampermonkey.net/uninstall.php` | Uninstall survey | Extension short ID (set via setUninstallURL) |
| `https://greasyfork.org/scripts/*` | Script repository | Script install/update requests |
| `https://openuserjs.org/scripts/*` | Script repository | Script install/update requests |
| `https://www.google.com/s2/favicons` | Favicon service | Domain name for favicon lookup |
| `https://icons.duckduckgo.com/ip2/` | Favicon fallback | Domain name for favicon lookup |

## Data Flow Summary

1. **Userscript Installation:** User installs scripts from repositories (greasyfork.org, openuserjs.org, etc.) or manually. Scripts are stored in `chrome.storage.local` / `unlimitedStorage`.
2. **Script Injection:** On page navigation, background.js matches URLs against script `@match`/`@include` patterns. Matching scripts are injected via content scripts and the `userScripts` API (MV3) or sandbox injection.
3. **GM API Proxying:** Content scripts proxy GM_* API calls (XHR, cookies, downloads, values, etc.) to the background script via `chrome.runtime.connect` ports.
4. **Cloud Sync (opt-in):** Users can sync scripts to Google Drive, Dropbox, OneDrive, or Yandex Disk via standard OAuth2 flows.
5. **Telemetry:** Anonymous Matomo analytics are sent to `a.tampermonkey.net` with sampling (1-50%). No PII or browsing data is included.
6. **Blacklist Check:** Script metadata is checked against `blacklist.tampermonkey.net` to warn users about known malicious userscripts.
7. **Favicon Caching:** Service worker (`cache.js`) caches favicon requests from Google and DuckDuckGo for the dashboard UI.

## Overall Risk Assessment

**CLEAN**

Tampermonkey is a legitimate, well-established userscript manager that has been in active development for over a decade. Its broad permission set is entirely justified by its core functionality of injecting and managing user-supplied JavaScript on any webpage. All network communication serves documented features (analytics, cloud sync, script repositories, blacklist). The anonymous Matomo telemetry is standard practice for extensions of this scale and does not collect PII or browsing content. No malicious behavior, unauthorized data collection, residential proxy infrastructure, market intelligence SDKs, or suspicious obfuscation was identified.
