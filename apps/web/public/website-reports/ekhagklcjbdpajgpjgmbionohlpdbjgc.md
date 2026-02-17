# Vulnerability Report: Zotero Connector

## Metadata
| Field | Value |
|-------|-------|
| Extension Name | Zotero Connector |
| Extension ID | ekhagklcjbdpajgpjgmbionohlpdbjgc |
| Version | 5.0.195 |
| Manifest Version | 3 |
| Users | ~7,000,000 |
| Publisher | Corporation for Digital Scholarship / Zotero.org |
| License | GNU Affero General Public License v3 (AGPLv3) |
| Homepage | https://www.zotero.org/ |

## Executive Summary

Zotero Connector is a well-known, open-source academic reference management browser extension developed by the Corporation for Digital Scholarship. It saves bibliographic references from web pages into the Zotero desktop application or the Zotero web library. The extension requests broad permissions (all URLs, cookies, tabs, webRequest, scripting) which are justified by its need to detect and extract citation data from arbitrary academic websites, manage proxy redirections for institutional access, and communicate with the local Zotero desktop client.

The codebase is clean, well-documented with AGPL license headers throughout, and contains no obfuscation, no third-party analytics/tracking SDKs, no ad injection, no residential proxy infrastructure, and no malicious behavior. All network communication is directed exclusively to legitimate Zotero-owned domains (zotero.org, api.zotero.org, repo.zotero.org) and Google APIs (for Google Docs integration). The extension communicates with the local Zotero desktop client via localhost HTTP.

## Vulnerability Details

### 1. Translator Sandbox eval() Usage
- **Severity**: LOW
- **File**: `deobfuscated/inject/sandboxManager.js` (line 63)
- **Code**:
  ```javascript
  "eval":function(code, functions) {
      // Prepend sandbox properties within eval environment
      for (var prop in this.sandbox) {
          code = 'var ' + prop + ' = this.sandbox.' + prop + ';' + code;
      }
      // Eval in a closure
      (function() {
          eval(code);
      }).call(this);
  }
  ```
- **Verdict**: FALSE POSITIVE. This is part of the Zotero translator sandbox system. Translator code is fetched from the official Zotero repository (`repo.zotero.org`) or from the local Zotero desktop client -- both trusted sources controlled by the Zotero project. The eval runs translator scripts that parse academic websites for bibliographic metadata. This is a core architectural pattern of the Zotero ecosystem and is well-documented open-source behavior. The CSP in the manifest (`script-src 'self'`) prevents arbitrary remote code execution on extension pages.

### 2. Active URL Reporting to Local Client
- **Severity**: LOW
- **File**: `deobfuscated/connector.js` (lines 58-63)
- **Code**:
  ```javascript
  this.reportActiveURL = function(url) {
      if (!this.isOnline || !this.prefs.reportActiveURL) return;
      let payload = { activeURL: url };
      this.ping(payload);
  }
  ```
- **Verdict**: FALSE POSITIVE. This sends the currently active tab URL to the **locally running Zotero desktop application** (via localhost HTTP, typically `http://127.0.0.1:23119/connector/ping`). This feature allows the Zotero desktop app to auto-detect when the user navigates to a page with a related reference, enabling proactive citation suggestions. The feature is: (a) only active when the local Zotero client is running, (b) controlled by a preference (`reportActiveURL`) that can be disabled, and (c) data never leaves the user's machine. No data is sent to external servers.

### 3. Cookie Access for Attachment Downloads
- **Severity**: LOW
- **File**: `deobfuscated/connector.js` (lines 227-283)
- **Code**:
  ```javascript
  this.callMethodWithCookies = async function(options, data, tab) {
      let cookies = await browser.cookies.getAll(cookieParams)
      // ...
      data.detailedCookies = cookieHeader.substr(1);
      data.uri = tab.url;
      return this.callMethod(options, data, tab);
  }
  ```
- **Verdict**: FALSE POSITIVE. Cookies are collected for the current page URL and forwarded to the **local Zotero desktop client** to enable it to download attachments (PDFs, etc.) from authenticated academic resources. The cookies are sent via localhost HTTP, never to external servers. This is a standard pattern for browser-to-desktop application integration when the desktop app needs to download files behind authentication.

### 4. OAuth Client Secret Embedded in Config
- **Severity**: LOW
- **File**: `deobfuscated/zotero_config.js` (lines 39-53)
- **Code**:
  ```javascript
  OAUTH: {
      ZOTERO: {
          CLIENT_KEY: '05a4e25d3d9af8922eb9',
          CLIENT_SECRET: '8dda1d6aa188bdd3126e'
      },
      GOOGLE_DOCS: {
          CLIENT_KEY: '222339878061-13uqre19u268oo9pdapuaifklbu8d6js.apps.googleusercontent.com',
      }
  }
  ```
- **Verdict**: INFORMATIONAL. OAuth 1.0 client credentials for the Zotero API and Google Docs integration are embedded in the source. This is standard practice for browser extensions using OAuth, as there is no secure way to store client secrets in a browser extension. The Zotero OAuth flow still requires user authorization, and the Google OAuth client key is a public identifier. This is consistent with the open-source nature of the project.

## False Positive Table

| Pattern | File | Reason |
|---------|------|--------|
| eval() | inject/sandboxManager.js | Translator sandbox -- executes trusted Zotero translator code from official repo |
| browser.cookies.getAll() | connector.js, itemSaver_background.js, http.js | Forwarding cookies to local Zotero client for authenticated attachment downloads |
| document.cookie | itemSaver.js, translate/translation/translate.js, http.js | Safari-specific cookie handling for authenticated requests; passed to local client only |
| reportActiveURL | connector.js, background.js | Sends URL to localhost Zotero client only, preference-controlled, never leaves machine |
| chrome.scripting.executeScript | background.js | Standard MV3 script injection API for content scripts defined in manifest |
| Proxy URL redirection | proxy.js | Academic library proxy management (EZProxy, Juniper) -- standard academic functionality |
| atob() | singlefile.js, utilities.js | Base64 decoding for file/attachment data handling, not obfuscation |
| webRequest interception | webRequestIntercept.js | PDF detection in frames and header manipulation for translator HTTP requests |

## API Endpoints Table

| Endpoint | Purpose | Direction |
|----------|---------|-----------|
| `http://127.0.0.1:23119/connector/*` | Local Zotero desktop client communication | Localhost only |
| `https://repo.zotero.org/repo/` | Translator metadata and code updates | Outbound to Zotero |
| `https://repo.zotero.org/settings` | Extension settings | Outbound to Zotero |
| `https://api.zotero.org/` | Zotero Web API (saving items to online library) | Outbound to Zotero |
| `https://www.zotero.org/oauth/*` | OAuth authorization flow | Outbound to Zotero |
| `https://script.googleapis.com/v1/scripts/...` | Google Docs integration (Apps Script) | Outbound to Google |
| `https://accounts.google.com/o/oauth2/v2/auth` | Google OAuth for Docs integration | Outbound to Google |
| `https://www.googleapis.com/oauth2/v3/tokeninfo` | Google OAuth token verification | Outbound to Google |

## Data Flow Summary

1. **Page Detection**: Content scripts are injected into all HTTP(S) pages. They parse the DOM to detect translatable academic content (journal articles, books, etc.) using Zotero's translator framework.
2. **Translator Execution**: When a matching translator is found, it extracts structured bibliographic metadata (title, authors, DOI, etc.) from the page.
3. **Save to Zotero**: Extracted metadata is sent to the local Zotero desktop client via localhost HTTP (`127.0.0.1:23119`). If Zotero is offline, items can be saved to the Zotero web API (`api.zotero.org`) using OAuth credentials.
4. **Attachment Download**: Cookies for the current page are forwarded to the local Zotero client so it can download PDFs and other attachments from authenticated academic resources. Alternatively, the connector can download and upload attachments directly.
5. **Proxy Management**: The extension detects and manages academic library proxy URLs (EZProxy, Juniper) to properly resolve and redirect URLs through institutional proxies.
6. **Translator Updates**: Translator scripts are periodically synced from the local Zotero client or the Zotero repository server (`repo.zotero.org`).
7. **Google Docs Integration**: Content scripts are injected into Google Docs to enable citation insertion and bibliography management via the Zotero desktop client and Google Apps Script API.

## Overall Risk Assessment

**CLEAN**

Zotero Connector is a legitimate, well-established, open-source academic tool with approximately 7 million users. The broad permissions (all URLs, cookies, tabs, webRequest, scripting) are justified by its core functionality: detecting citation metadata on arbitrary academic websites, managing institutional proxy redirections, forwarding authentication cookies for attachment downloads, and integrating with Google Docs.

Key factors supporting the CLEAN assessment:
- **Open source** under AGPLv3 with consistent license headers across all source files
- **No obfuscation** -- all code is readable and well-structured
- **No analytics/tracking SDKs** -- zero third-party telemetry, no Sensor Tower, no Pathmatics, no ad networks
- **No ad/coupon injection** -- no DOM manipulation for advertising purposes
- **No extension enumeration** -- does not probe for or disable other extensions
- **No residential proxy behavior** -- proxy code is exclusively for academic library proxy management
- **No remote config/kill switches** -- translator updates come from the official Zotero repo
- **No keylogging or credential harvesting** -- no keyboard event listeners for password fields
- **All network traffic goes to legitimate, expected destinations** -- zotero.org domains, localhost, Google APIs
- **reportActiveURL only sends data to localhost** Zotero client, never to external servers, and is preference-controlled
- **Cookie access is functional** -- forwarding cookies to the local client for authenticated downloads is core to the extension's purpose
