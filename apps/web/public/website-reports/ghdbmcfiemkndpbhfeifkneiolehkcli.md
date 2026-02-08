# VULN_REPORT: FUJIFILM Synapse Extension

## Metadata
| Field | Value |
|---|---|
| Extension Name | FUJIFILM Synapse Extension |
| Extension ID | ghdbmcfiemkndpbhfeifkneiolehkcli |
| Version | 7.4.310.1 |
| Manifest Version | 3 |
| Users | ~3,000,000 |
| Publisher | FUJIFILM Healthcare Americas Corporation |
| Description | Native Messaging and Window Management for FUJIFILM Synapse PACS |

## Executive Summary

FUJIFILM Synapse Extension is a legitimate enterprise healthcare PACS (Picture Archiving and Communication System) companion extension. It bridges the Chrome browser with a local native messaging host (`fujifilm.synapse.nativemessaging`) to enable medical imaging workflow features: launching native viewers, managing multi-window layouts for radiology workstations, cursor locking for diagnostic tools, direct printing, registry access, and polling for subscription updates.

The extension is narrowly scoped to Synapse-specific URL patterns (SynapseSignOn, ImageViewer, PowerJacket, WorkflowUI, WebQuery, ThinkLogChat, etc.) and does not inject into arbitrary websites. It makes no external network requests to third-party analytics, advertising, or tracking services. All communication flows between the content scripts, background service worker, and the local native messaging host.

**No malicious behavior, data exfiltration, or significant vulnerabilities were identified.**

## Vulnerability Details

### LOW-1: Web-Accessible Canary Resources Enable Extension Detection
- **Severity:** LOW
- **Files:** `manifest.json` (lines 37-41)
- **Code:**
  ```json
  "web_accessible_resources": [
    {
      "resources": [ "canary.png", "canary.1.0.12.png" ],
      "matches": [ "<all_urls>" ]
    }
  ]
  ```
- **Verdict:** The canary PNG files are accessible from `<all_urls>`, meaning any website can probe for the existence of this extension by attempting to load `chrome-extension://ghdbmcfiemkndpbhfeifkneiolehkcli/canary.png`. This is a common pattern used by Synapse web applications to detect whether the extension is installed, but it also allows any page to fingerprint the user as a FUJIFILM Synapse user (likely a healthcare/radiology professional). This is an information disclosure issue but is intentional functionality and very low risk.

### LOW-2: Content Script Exposes Hostname via DOM Attribute
- **Severity:** LOW
- **Files:** `csNativeMessage.js` (lines 19, 43-46)
- **Code:**
  ```javascript
  document.documentElement.setAttribute("hostName", hostName);
  localStorage.setItem("Synapse.Extension.HostName", hostName);
  ```
- **Verdict:** The machine hostname is written to the DOM `documentElement` attribute and localStorage. This is accessible to the host page's JavaScript. Since content scripts only run on Synapse-owned URLs (not arbitrary sites), the exposure surface is limited to the Synapse web application itself, which presumably already knows the hostname. Low risk in practice.

### INFO-1: Native Messaging Host Can Execute Arbitrary Local Operations
- **Severity:** INFO
- **Files:** `bsNativeMessage.js` (line 23), `csNativeMessage.js` (lines 123-133, 319-343)
- **Code:**
  ```javascript
  chrome.runtime.connectNative("fujifilm.synapse.nativemessaging");
  // Content script dispatches: LaunchApplication, GetRegistryValue, SetRegistryValue, etc.
  ```
- **Verdict:** The extension proxies commands to a native messaging host that can launch applications, read/write Windows registry values, lock/release cursor, get memory usage, and perform direct printing. This is powerful functionality but is expected and intentional for an enterprise radiology PACS workstation extension. The native host must be separately installed on the machine, and the extension only communicates with it from Synapse-specific URLs. This is not a vulnerability but is noted for completeness.

### INFO-2: Polling Mechanism Fetches URLs with Authorization Headers
- **Severity:** INFO
- **Files:** `bsWindowManagement.js` (lines 528-563)
- **Code:**
  ```javascript
  async function fetchUrl(url, authorization, contentType) {
      const response = await fetch(url, {
          method: "GET",
          headers: {
              Authorization: authorization,
              'Content-Type': contentType
          }
      });
      return await response.text();
  }
  ```
- **Verdict:** The polling mechanism fetches URLs with authorization headers. However, the URL, authorization token, and polling interval are all provided by the Synapse web application via content script messages -- not hardcoded to any external service. This is used for real-time subscription/notification updates within the Synapse ecosystem. The `host_permissions` only include `https://ajax.googleapis.com/` (likely for jQuery/utility loading), so fetch calls to Synapse servers rely on the server's CORS policy. No data exfiltration risk.

## False Positive Table

| Pattern | Location | Reason for FP Classification |
|---|---|---|
| `document.documentElement.setAttribute()` | csNativeMessage.js | Sets `native`, `extension`, `hostName` attributes for Synapse web app to detect extension -- standard inter-component communication |
| `localStorage.setItem()` | csNativeMessage.js | Stores hostname for Synapse session continuity -- not exfiltration |
| `chrome.tabs.query({})` | bsWindowManagement.js | Queries all tabs to find Synapse windows for close/open coordination -- not surveillance |
| `fetch()` with Authorization header | bsWindowManagement.js | Polling Synapse server for subscription updates -- not external data exfiltration |
| `chrome.runtime.connectNative()` | bsNativeMessage.js | Connects to legitimate FUJIFILM native messaging host for PACS functionality |
| `setInterval()` polling | bsWindowManagement.js | Heartbeat/subscription polling within Synapse ecosystem |

## API Endpoints Table

| Endpoint/Host | Purpose | File |
|---|---|---|
| `fujifilm.synapse.nativemessaging` (native host) | Native messaging bridge for local PACS operations | bsNativeMessage.js |
| `https://ajax.googleapis.com/` (host_permission) | CDN/utility loading (declared but not explicitly used in code) | manifest.json |
| Dynamic polling URL (from Synapse app) | Subscription status polling | bsWindowManagement.js |

## Data Flow Summary

1. **Extension Detection:** Synapse web pages detect the extension via canary.png resource probe and `extension`/`native` DOM attributes.
2. **Native Messaging:** Content scripts on Synapse pages send commands (LaunchApplication, GetRegistryValue, SetRegistryValue, LockCursor, DirectPrint, etc.) via `chrome.runtime.sendMessage()` to the background service worker, which relays them to the local `fujifilm.synapse.nativemessaging` native host via `port.postMessage()`.
3. **Window Management:** The Synapse web application requests window operations (open, close, move, resize, maximize, minimize, focus, restore) via custom DOM events, which content scripts relay to the background service worker that uses `chrome.windows.*` and `chrome.tabs.*` APIs.
4. **Polling:** The background script can poll a Synapse server URL (provided by the web app) at intervals with authorization headers, relaying responses back to content scripts.
5. **Heartbeat:** A 20-second heartbeat keeps the MV3 service worker alive while Synapse windows are open.

No data leaves the Synapse ecosystem. No third-party analytics, tracking, or advertising SDKs are present. No obfuscation is used.

## Overall Risk: **CLEAN**

This is a legitimate enterprise healthcare extension by FUJIFILM Healthcare Americas Corporation for their Synapse PACS radiology platform. It uses `nativeMessaging`, `tabs`, `storage`, and `system.display` permissions -- all necessary for its intended multi-window radiology workstation management purpose. Content scripts are narrowly scoped to Synapse-specific URL patterns. No malicious behavior, data exfiltration, remote code execution, or significant vulnerabilities were found. The only minor issues are extension fingerprinting via web-accessible resources and hostname exposure in DOM attributes, both of which are intentional design choices for the Synapse integration workflow.
