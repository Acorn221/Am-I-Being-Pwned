# Vulnerability Report: Lightspeed Insight Agent

## Metadata
| Field | Value |
|-------|-------|
| Extension Name | Lightspeed Insight Agent |
| Extension ID | njdniclgegijdcdliklgieicanpmcngj |
| Version | 3.8.3 |
| Manifest Version | 3 |
| Users | ~7,000,000 |
| Developer | Lightspeed Systems (Zscaler subsidiary) |
| Purpose | K-12 school IT analytics: browsing activity tracking, speed testing, digital equity monitoring |

## Executive Summary

Lightspeed Insight Agent is a **legitimate enterprise/education monitoring tool** deployed by K-12 school administrators to track student browsing activity, run internet speed tests, and collect digital equity data (device specs, connectivity, geolocation). The extension is designed to be managed via Chrome Enterprise policy (`chrome.storage.managed`) and requires an entitlement key provisioned by the school.

The extension collects every URL visited by the user (via `<all_urls>` content script), tracks user interaction events (clicks, keystrokes, scroll, video playback), collects device hardware info (CPU, memory, storage), geolocation, IP address, and user email (hashed by default, PII collection configurable server-side). All data is sent to `agent.catchon.com` (Lightspeed/Catchon infrastructure). A Go-compiled WASM binary handles speed testing against `insight-speedtest.lightspeedsystems.app`.

While the data collection is invasive, it is **entirely consistent with the extension's stated purpose** as a school-administered monitoring agent. There is no obfuscation, no hidden data exfiltration, no dynamic code injection, no extension enumeration, no ad injection, and no residential proxy behavior.

## Vulnerability Details

### VULN-01: Full URL Tracking of All Browsing Activity
| Field | Value |
|-------|-------|
| Severity | **MEDIUM** (Privacy) |
| Files | `js/user-interaction.js`, `background.js` |
| Verdict | **Intended Functionality** |

The content script (`user-interaction.js`) is injected into every page (`<all_urls>`) and tracks:
- Click events
- Keyup events (event type only, NOT keystrokes/content)
- Scroll events (debounced)
- Touch events
- Video playback status (every 10 seconds)

Each event sends `{ event, url: window.location.href }` to the background script. The background script (`background.js`) tracks all tab URLs with timestamps and time-on-page intervals, then batches and sends the activity list to `config.endpointURL` every 15 minutes (configurable).

```javascript
// user-interaction.js
const track = (event) => port.postMessage({
  event,
  url: window.location.href,
});
document.addEventListener('click', () => track('click'), false);
document.addEventListener('keyup', () => track('keyup'), false);
```

**Note:** The `keyup` listener only fires to signal user activity -- it does NOT capture key values, characters, or any keystroke content. This is NOT a keylogger.

### VULN-02: Server-Controlled PII Collection Toggle
| Field | Value |
|-------|-------|
| Severity | **LOW** |
| Files | `background.js` (line 244-249), `env/prod.json` |
| Verdict | **Intended Functionality - Configurable** |

PII collection (email, username, domain, hostname) is controlled by a server-side `collectPII` flag. Default in prod config is `false`, but the server can toggle it to `true` at any time via the `agentConfigUrl` endpoint.

```javascript
const getPIIData = (userData, hostname) => (config.collectPII ? {
  Email: userData.email,
  Username: userData.username,
  Domain: userData.domain,
  Hostname: hostname,
} : undefined);
```

When `collectPII` is `false`, users are identified only by `md5(email)` hash.

### VULN-03: Remote Configuration / Kill Switch
| Field | Value |
|-------|-------|
| Severity | **LOW** |
| Files | `js/api.js`, `background.js` |
| Verdict | **Intended Functionality** |

The extension polls `agent.catchon.com/agentconfig/v2/{platform}/{key}` every ~10 minutes to fetch configuration. The server can remotely control:
- `active` - enable/disable all data collection
- `collectPII` - toggle PII collection
- `sendInterval` - data send frequency
- `speedTestActive` / `locationDataActive` - toggle speed test and geolocation
- `inactiveTimeout` - idle detection threshold
- `speedTestURL` / `chunkSize` / `chunkCount` - speed test parameters

This is standard MDM-style remote configuration for enterprise software.

### VULN-04: Geolocation Collection
| Field | Value |
|-------|-------|
| Severity | **LOW** |
| Files | `background.js`, `location.html`, `js/location.js` |
| Verdict | **Intended Functionality** |

When `locationDataActive` is `true` (default: `false` in prod), the extension uses an offscreen document to request geolocation via `navigator.geolocation.getCurrentPosition`. Coordinates are sent with digital equity data. This is gated behind server-side config and the browser's standard geolocation permission prompt.

### VULN-05: Hardware Fingerprinting / Device Telemetry
| Field | Value |
|-------|-------|
| Severity | **LOW** |
| Files | `js/identity.js`, `background.js` |
| Verdict | **Intended Functionality** |

The extension collects detailed device information:
- CPU model, core count, architecture (`chrome.system.cpu`)
- Storage capacity and type (`chrome.system.storage`)
- Memory total and available (`chrome.system.memory`)
- Device serial number (`chrome.enterprise.deviceAttributes`)
- OS version, device type, platform

This data is sent as part of "digital equity" reporting, intended to help schools assess technology resources across student populations.

### VULN-06: WASM Binary for Speed Testing
| Field | Value |
|-------|-------|
| Severity | **INFO** |
| Files | `client.wasm`, `js/speed_test.js`, `js/wasm_exec.js` |
| Verdict | **Intended Functionality** |

The extension includes a 10.5MB Go-compiled WASM binary (`client.wasm`) used for speed testing. String analysis confirms it contains:
- `github.com/Lightspeed-Systems/insight-speedtest/speedtestclient` - legitimate Lightspeed repo
- Standard Go `net/http` library for HTTP-based speed testing
- `RunSpeedTest` / `runSpeedTest` entry points

The `wasm_exec.js` is the standard Go WASM runtime shim (copyright The Go Authors). The WASM binary communicates only with the speed test server configured by the admin.

## False Positive Table

| Pattern | Location | Reason |
|---------|----------|--------|
| `keyup` event listener | `js/user-interaction.js` | Tracks event TYPE only for idle detection, does NOT capture keystrokes |
| `<all_urls>` content script | `manifest.json` | Required for browsing activity monitoring - the stated purpose |
| `wasm-unsafe-eval` CSP | `manifest.json` | Required for Go WASM speed test binary |
| `chrome.identity.getProfileUserInfo` | `js/identity.js` | Used to get email for user identification (hashed by default) |
| `chrome.enterprise.deviceAttributes` | `js/identity.js` | Enterprise API for device serial - only works on managed devices |
| MD5 hashing | `js/md5.js` | Used to hash email for pseudonymization, not for security |
| `innerHTML` / DOM manipulation | None | No DOM manipulation found |
| Remote config fetch | `js/api.js` | Standard enterprise config management pattern |

## API Endpoints Table

| Endpoint | Method | Purpose |
|----------|--------|---------|
| `https://agent.catchon.com/agentconfig/keys/verify/{key}` | GET | Validate entitlement key |
| `https://agent.catchon.com/agentconfig/v2/{platform}/{key}` | GET | Fetch agent configuration |
| `https://agent.catchon.com/catcher/api/receive` | POST | Send browsing activity data |
| `https://agent.catchon.com/catcher/api/receive-equity` | POST | Send digital equity / speed test data |
| `https://development-agent.catchon.com/...` | Various | Dev environment (same paths) |
| `https://staging-agent.catchon.com/...` | Various | Staging environment (same paths) |
| `insight-speedtest.lightspeedsystems.app` | Various | Speed test server (prod) |

## Data Flow Summary

1. **Startup**: Extension loads config from `chrome.storage.managed` (set by school admin) or fetches defaults from `env/prod.json`. Validates entitlement key with server.
2. **Config Polling**: Every ~10 minutes, fetches latest config from `agentConfigUrl`. Server controls collection behavior.
3. **Activity Tracking**: Content script on all pages reports user interaction events (click, keyup, scroll, touch, video) to background. Background tracks URL + time intervals per hour.
4. **Activity Sending**: Every ~15 minutes, batched activity data (URLs, timestamps, intervals) is POSTed to `endpointURL` with device ID, user hash, platform info.
5. **Speed Test** (when enabled): WASM binary runs download speed test against configured server. Results sent with device hardware info and optional geolocation to `digitalEquityURL`.
6. **Offline Tracking** (when enabled): Tracks disconnection intervals and reports them when connectivity resumes.

**Data collected:**
- Every URL visited with timestamps and active time intervals
- User email hash (MD5), optionally full email/username/domain
- Device serial / generated UUID
- CPU, memory, storage, OS info
- IP address (from response headers)
- Geolocation (when enabled)
- Internet speed test results

**No data collected:**
- Page content, form data, passwords
- Keystroke content (only event type)
- Cookie values
- DOM content

## Overall Risk Assessment

**CLEAN**

This is a legitimate enterprise/education monitoring extension from Lightspeed Systems (acquired by Zscaler), a well-known K-12 technology management vendor. The extensive data collection (full browsing history, device fingerprinting, geolocation, speed testing) is invasive but entirely consistent with the product's stated purpose as a school IT analytics tool. The code is clean, well-structured, not obfuscated, and contains no signs of malicious behavior:

- No dynamic code execution (`eval`, `new Function`, etc.)
- No extension enumeration or competitor killing
- No XHR/fetch hooking or prototype pollution
- No residential proxy or traffic tunneling
- No ad/coupon injection
- No market intelligence SDK
- No AI conversation scraping
- No cookie harvesting or credential theft
- No hidden data exfiltration beyond documented endpoints
- Server communication limited to Lightspeed/Catchon infrastructure
- Enterprise-managed deployment model (requires admin-provisioned key)
