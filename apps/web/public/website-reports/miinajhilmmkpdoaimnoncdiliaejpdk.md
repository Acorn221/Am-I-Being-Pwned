# Vulnerability Report: Nexthink Browser Extension

## Metadata
| Field | Value |
|-------|-------|
| Extension Name | Nexthink |
| Extension ID | miinajhilmmkpdoaimnoncdiliaejpdk |
| Version | 26.1.2 |
| Manifest Version | 3 |
| User Count | ~7,000,000 |
| Publisher | Nexthink (enterprise IT experience management) |

## Executive Summary

Nexthink is a legitimate enterprise Digital Experience Monitoring (DEM) and Digital Adoption Platform (DAP) extension. It is deployed by IT administrators to monitor web application performance metrics (page load times, network resource timings, DOM mutations, long tasks) and provide in-app guidance (via the bundled AppLearn/Adopt platform). The extension uses extensive permissions and collects significant telemetry data, but all data flows are directed to the organization's own Nexthink cloud tenant (`*.nexthink.cloud`, `*.nexthink.com`). There is no evidence of malicious behavior, data exfiltration to unauthorized third parties, or hidden functionality.

The extension monitors AI tool usage (via its "AI Dexterity" feature) but only sends metadata (tool ID, rule ID, usage type, timestamp) -- NOT conversation content or request bodies. Request body logging only activates in development mode. It also enumerates installed browser extensions and reports them to the Nexthink collector, which is standard enterprise endpoint management behavior.

**Overall Risk: CLEAN**

This extension requires many permissions and is invasive by design (it is enterprise endpoint monitoring software), but it serves its clearly intended purpose with no malicious behavior or key vulnerabilities identified.

## Permissions Analysis

| Permission | Justification |
|-----------|---------------|
| `<all_urls>` (host) | Monitor web app performance on all sites configured by IT admin |
| `downloads` | Download reports/guides |
| `idle` | Detect user idle state for session metrics |
| `nativeMessaging` | Communicate with Nexthink Collector desktop agent (`com.nexthink.chrome.extension`) |
| `scripting` | Inject content scripts for performance monitoring and digital adoption guides |
| `storage` | Store configuration, session state, EULA acceptance |
| `tabs` | Monitor tab navigation, URL changes for app identification |
| `webNavigation` | Track navigation events, DOMContentLoaded, history state changes |
| `webRequest` | Monitor XHR/fetch requests for performance timing and AI tool usage detection |
| `contextMenus` | Right-click menu integration |
| `identity` | OAuth flow for tenant authentication |
| `unlimitedStorage` | Store telemetry data locally before sending to collector |

## Content Security Policy

```
default-src 'none';
script-src 'self';
style-src 'self' 'unsafe-inline';
connect-src https://*.nexthink.cloud https://*.nexthink.com wss://*.nexthink.cloud wss://*.nexthink.com;
```

**Verdict:** Strong CSP. Only connects to Nexthink's own domains. No remote code loading possible.

## Vulnerability Details

### 1. Extension Enumeration via management.getAll()
- **Severity:** LOW (enterprise intended behavior)
- **File:** `background.js`
- **Code:** `this.browser.management.getAll()` -> `this.collector.postInstalledExtensions(e)`
- **Details:** Enumerates all installed extensions (name, version, ID, install type, permissions) and sends to Nexthink collector via native messaging.
- **Verdict:** FALSE POSITIVE -- This is standard enterprise endpoint management behavior. The data goes to the organization's own Nexthink tenant, not to third parties. IT administrators need this visibility for security compliance.

### 2. AI Tool Usage Monitoring ("AI Dexterity")
- **Severity:** LOW (enterprise intended behavior)
- **File:** `background.js`
- **Code:** `ox().webRequest.onBeforeRequest.addListener(this.onBeforeRequest, this.requestFilter, this.extraInfoSpec)` with `extraInfoSpec: ["requestBody"]`
- **Details:** Monitors POST requests to AI tools (ChatGPT, etc.) on monitored tabs. However, only metadata is sent:
  - `usageType: USAGE_TYPE_WEB`
  - `eventTime: new Date`
  - `aiToolId` (UUID)
  - `hostApplication: "browser"`
  - `interactionEndpointId` (rule ID)
- **Verdict:** CLEAN -- Only usage frequency/metadata is reported, NOT conversation content. Request body logging is development-only (`isDevelopment()` guard). This is an enterprise feature for measuring AI tool adoption rates.

### 3. WebRequest Interception on All URLs
- **Severity:** LOW
- **File:** `background.js`
- **Code:** `e.onBeforeRequest.addListener(this.handleWebRequestBefore, this.webRequestFilter)`
- **Details:** Monitors web requests for performance timing (redirect, DNS lookup, connect, response times). Tracks XHR completion for page readiness detection.
- **Verdict:** FALSE POSITIVE -- Performance monitoring is the core purpose. Data is used to compute page load metrics and sent to Nexthink tenant.

### 4. Content Script Injection via scripting.executeScript
- **Severity:** LOW
- **File:** `background.js`
- **Code:** `ox().scripting.executeScript({files: this.configuration.contentScripts, target: {tabId, frameIds}})`
- **Details:** Dynamically injects content scripts (adopt.js, appex.js, functional-error.js, guide-recording.js) into monitored pages.
- **Verdict:** CLEAN -- Scripts are bundled with the extension (not loaded remotely). Injection is for digital adoption guides and performance monitoring.

### 5. Native Messaging to Desktop Agent
- **Severity:** LOW (enterprise intended behavior)
- **File:** `background.js`
- **Code:** `ox().runtime.connectNative(this.nativeHostId)` where nativeHostId = `com.nexthink.chrome.extension`
- **Details:** Maintains persistent connection to Nexthink Collector desktop agent. Sends beacons, performance metrics, installed extensions, AI usage events, and keep-alive messages.
- **Verdict:** CLEAN -- This is the primary data channel. Data goes to the locally-installed Nexthink Collector which forwards to the organization's Nexthink cloud tenant.

## False Positive Table

| Pattern | Location | Reason |
|---------|----------|--------|
| `eval()` | None found | No eval usage |
| `new Function()` | None found | No dynamic code execution |
| `innerHTML` (252 occurrences) | `content/adopt.js` | Froala WYSIWYG editor (bundled for guide creation) and React rendering |
| `keydown/keypress` listeners | `content/adopt.js` | Froala WYSIWYG editor keyboard shortcuts, React synthetic events |
| `document.cookie` access | `content/adopt.js` | Datadog RUM SDK domain detection (`_gd` cookie pattern) |
| `postMessage` usage | `background.js`, `content/adopt.js` | Internal extension messaging between content scripts and background |
| `proxy` references | `background.js` | Protobuf field for Nexthink proxy infrastructure (ConnectedProxy, proxyId) -- network topology metadata |
| `featureFlag` references | `background.js` | Standard feature flag system for enabling/disabling monitoring capabilities |
| `inject` references | `background.js` | Content script injection logic for digital adoption platform |
| Sentry SDK | `background.js` | Error reporting (`o783994.ingest.us.sentry.io/5798986`) -- known FP |
| Datadog SDK | `background.js`, `content/adopt.js` | RUM/APM monitoring (`datadoghq-browser-agent.com`) -- known FP |
| `spyware` references | `background.js` | Protobuf field for endpoint security status reporting (`antispyware` field in device health metrics) |
| `MutationObserver` | `content/adopt.js` | DOM change detection for page readiness and guide overlay rendering |

## API Endpoints Table

| Endpoint | Purpose | Method |
|----------|---------|--------|
| `https://*.nexthink.cloud` | Nexthink cloud tenant API | Various |
| `wss://*.nexthink.cloud` | WebSocket connection for real-time config updates | WSS |
| `https://*.nexthink.com` | Nexthink corporate API | Various |
| `wss://*.nexthink.com` | WebSocket fallback | WSS |
| `https://sdk-configuration.{tenant}.nexthink.cloud` | SDK configuration endpoint | GET |
| `https://dap-dev-login.eu.dev.nexthink.cloud` | Dev environment login (hardcoded dev URL) | GET |
| `https://app.eu-dev.applearn.tv` | AppLearn/Adopt digital adoption platform API (dev) | Various |
| `wss://yeal-app.eu-dev.applearn.tv/events` | AppLearn WebSocket events (dev) | WSS |
| `https://auth.eu-dev.applearn.tv/auth` | AppLearn OAuth/OIDC (dev) | POST |
| `https://o783994.ingest.us.sentry.io/5798986` | Sentry error reporting (background) | POST |
| `https://c344f0363028300dc2b39120c14662c7@o783994.ingest.us.sentry.io/4507374135803904` | Sentry error reporting (Adopt) | POST |
| Native: `com.nexthink.chrome.extension` | Nexthink Collector desktop agent (Chrome) | Native Messaging |
| Native: `com.nexthink.edge.extension` | Nexthink Collector desktop agent (Edge) | Native Messaging |
| Native: `com.nexthink.firefox.extension` | Nexthink Collector desktop agent (Firefox) | Native Messaging |

## Data Flow Summary

1. **Configuration**: Extension connects to Nexthink cloud tenant via WSS to receive monitoring configuration (which apps to monitor, thresholds, feature flags, AI tool definitions, URL sanitization rules).

2. **Performance Monitoring**: Content scripts (appex.js) measure page load times, resource timings, DOM mutations, long tasks, and user interaction delays on configured applications. Data is sent to background script.

3. **Digital Adoption**: Content scripts (adopt.js, guide-recording.js) render in-app guides, tooltips, and walkthroughs powered by the AppLearn/Adopt platform. Guide recording captures user clicks for guide creation.

4. **AI Dexterity**: Background script monitors POST requests to configured AI tool URLs, sends usage metadata (tool ID, timestamp, rule ID) -- NOT request/response content.

5. **Extension Enumeration**: Periodically collects list of installed browser extensions with metadata.

6. **Data Egress**: All collected data flows through native messaging to the locally-installed Nexthink Collector agent, which forwards to the organization's Nexthink cloud tenant. URL sanitization and obfuscation are applied to protect PII in query parameters and URL fragments.

7. **Error Reporting**: Sentry SDK reports extension errors to Nexthink's Sentry instance. Datadog RUM SDK monitors the Adopt platform's own performance.

## Overall Risk Assessment

**CLEAN**

Nexthink is a well-known enterprise IT experience management platform (publicly traded company, NYSE: NXHK). This extension is deployed by enterprise IT administrators as part of their endpoint management stack. While it is highly invasive by design (monitoring all web traffic, enumerating extensions, tracking AI tool usage), this is its documented and intended purpose. All data flows are directed to the organization's own Nexthink tenant infrastructure. The CSP strictly limits connections to `*.nexthink.cloud` and `*.nexthink.com`. No evidence of:

- Malicious data exfiltration
- Residential proxy infrastructure
- Market intelligence SDK injection
- Ad/coupon injection
- AI conversation content scraping (only metadata)
- Remote code execution or dynamic code loading
- Kill switches or backdoors
- Obfuscated malicious logic

The extension is invasive but legitimate enterprise monitoring software.
