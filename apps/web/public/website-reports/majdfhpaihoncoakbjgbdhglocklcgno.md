# Vulnerability Report: Free VPN for Chrome - VPN Proxy VeePN

## Metadata
- **Extension Name:** Free VPN for Chrome - VPN Proxy VeePN
- **Extension ID:** majdfhpaihoncoakbjgbdhglocklcgno
- **Version:** 3.7.10
- **Manifest Version:** 3
- **User Count:** ~13,000,000
- **Homepage:** https://veepn.com/
- **Analysis Date:** 2026-02-08

## Executive Summary

VeePN is a commercial free/premium VPN Chrome extension that routes browser traffic through proxy servers via the `chrome.proxy` API using PAC scripts. The extension is built with modern tooling (Vite, React, i18next) and uses Manifest V3. It collects analytics through three services (Google Analytics, AWS Kinesis, Amplitude) and uses standard VPN architecture. The extension enumerates other installed extensions and reports them to analytics, and can disable competing proxy extensions. Content scripts inject promotional UI overlays (intro offers, lock screen banners) into all web pages. While the permissions are extensive, they are consistent with VPN functionality. No malware, residential proxy infrastructure, data exfiltration, or remote code execution was found.

## Vulnerability Details

### 1. Installed Extensions Enumeration and Exfiltration
- **Severity:** MEDIUM
- **File:** `assets/background.ts-Ceq_j6Wh.js`
- **Code:**
```javascript
async collectInstalledExtensions(){
  const e=new Date("2024-01-01").getTime();
  if(!(this.globalStateService.installedAt>e))return;
  (await r.management.getAll()).filter(a=>a.type==="extension"&&a.id!==r.runtime.id)
  .forEach(a=>{
    this.analyticsService.sendEvent({types:["aws-kinesis"],
      name:"user_external_extension_installed",
      data:{
        event_properties__external_extension_enabled:a.enabled,
        event_properties__external_extension_id:a.id,
        event_properties__external_extension_install_type:a.installType,
        event_properties__external_extension_name:a.name,
        event_properties__external_extension_short_name:a.shortName??"unknown",
        event_properties__external_extension_version:a.version
      }
    })
  })
}
```
- **Verdict:** The extension enumerates ALL installed extensions (name, ID, version, enabled status, install type) and sends each one to AWS Kinesis analytics on install/update. This is a privacy concern as it fingerprints the user's browser configuration and exfiltrates it. However, this is a known pattern for competitive intelligence in VPN extensions and is not inherently malicious -- it is used for product analytics.

### 2. Disabling Competing Proxy Extensions
- **Severity:** MEDIUM
- **File:** `assets/background.ts-Ceq_j6Wh.js`
- **Code:**
```javascript
static async getActiveExtensionsWithProxyPermition(){
  return(await r.management.getAll()).filter(s=>s.type==="extension"&&s.id!==r.runtime.id)
  .filter(s=>{const a=s.enabled,o=s.permissions?.includes("proxy");return a&&o})
}
async disableProxyControlExtensions(){
  const e=await z.getActiveExtensionsWithProxyPermition();
  return await Promise.all(e.map(t=>r.management.setEnabled(t.id,!1))),
  {success:!0,data:{success:!0}}
}
```
- **Verdict:** The extension can identify and disable all other extensions that have the `proxy` permission. This is triggered via a user-facing UI action (not automatically) when proxy control conflicts are detected. While aggressive, this is a common pattern in VPN extensions to resolve proxy conflicts. The feature only activates when the user explicitly clicks to resolve a proxy conflict.

### 3. Broad Content Script Injection with Promotional Overlays
- **Severity:** LOW
- **Files:** `assets/main.tsx-BBq4WnBe.js`, `assets/main.tsx-DWHsIPRg.js`
- **Code:** Content scripts inject `<veepn-intro-offer>` and `<veepn-lock-screen>` custom elements into every HTTP/HTTPS page (excluding veepn.com). These display premium upgrade popups/banners.
- **Verdict:** The injected content is purely promotional (upselling premium plans). It uses Shadow DOM for encapsulation. No DOM manipulation of the host page, no form interception, no keylogging, no data scraping. This is annoying but not a security vulnerability.

### 4. Triple Analytics Pipeline
- **Severity:** LOW
- **File:** `assets/background.ts-Ceq_j6Wh.js`
- **Endpoints:**
  - Google Analytics: `https://www.google-analytics.com/mp/collect` (measurement ID: G-JY9WLXGNHW)
  - AWS Kinesis: `https://oovttlsctrmbll4c3pxzbi55na0vbuln.lambda-url.us-west-2.on.aws/`
  - Amplitude: `https://api2.amplitude.com/2/httpapi` (API key: 349c341094927d0c67a38a15e4cfbfdc)
- **Data sent:** UDID, user type, plan, version, platform, country, region, browser, OS, language, screen dimensions, theme preferences, connection events, IP address, session data, installed extensions list.
- **Verdict:** Extensive telemetry but standard for a commercial VPN product. The data collected is consistent with product analytics needs. The UDID is auto-generated, not tied to personal identity directly. IP address is collected as part of VPN connection verification (via Cloudflare 1.1.1.1 trace).

### 5. Reserve Domain Fallback System
- **Severity:** LOW
- **File:** `assets/index-DJIomh0c.js`
- **Code:**
```javascript
const Lt="https://antpeak.com"
const Nt="https://zorvian.com"
const X="https://s3-oregon-1.s3-us-west-2.amazonaws.com/api.json"
const J="https://proigor.com/payload.json"
```
- **Verdict:** The extension has a domain fallback system where if the primary API domains (antpeak.com for free, zorvian.com for premium) are unavailable, it fetches a list of reserve domains from S3 buckets or proigor.com. This is a common resilience pattern for VPN services that may face DNS blocking. The fetched data is validated against a strict schema (`$t.safeParse`). No remote code execution potential.

### 6. A/B Testing Cookie on External Domain
- **Severity:** LOW
- **File:** `assets/index-DplEc9UF.js`
- **Code:**
```javascript
const u="https://veepn.com/"
const l="https://fake-veepn.com/"
const p="veepn-ab-tests"
// Sets cookies on veepn.com and fake-veepn.com for A/B test state
```
- **Verdict:** The extension sets cookies on veepn.com (owned by VeePN) and fake-veepn.com (a domain they control for internal state tracking). This is used for A/B testing experiment persistence. The cookies permission is used legitimately.

## False Positive Table

| Pattern | File | Reason |
|---------|------|--------|
| `innerHTML` | `client-Da0e5-BC.js`, `webcomponents-bundle-Cazg7WE4.js` | React/Lit DOM rendering internals |
| `innerHTML` | `upgrade-Ch0YeFff.js`, `popup.html-L3fm1Z2r.js` | React rendering, standard UI components |
| `postMessage` | `index-DA4uJ5Kf.js`, `background.ts-Ceq_j6Wh.js` | Chrome extension port messaging (runtime.onConnect) |
| `eval`-like patterns | None found | No eval, new Function, or dynamic code execution |
| `document.cookie` | Not used | Extension uses chrome.cookies API, not document.cookie |
| `injectTime` | `main.tsx-loader-*.js` | Vite content script loader -- performance timing, not injection |
| `onelink-smart-script` | `js/onelink-smart-script-*.js` | AppsFlyer attribution SDK for desktop app download tracking (welcome page only) |

## API Endpoints Table

| Endpoint | Purpose | Method |
|----------|---------|--------|
| `https://antpeak.com/api/*` | Free tier API (launch, locations, servers) | POST |
| `https://zorvian.com/api/*` | Premium tier API (auth, locations, servers) | POST |
| `https://s3-oregon-1.s3-us-west-2.amazonaws.com/api.json` | Reserve domain list | GET |
| `https://proigor.com/payload.json` | Reserve domain list (RU fallback) | GET |
| `https://www.google-analytics.com/mp/collect` | Google Analytics telemetry | POST |
| `https://oovttlsctrmbll4c3pxzbi55na0vbuln.lambda-url.us-west-2.on.aws/` | AWS Kinesis analytics | POST |
| `https://api2.amplitude.com/2/httpapi` | Amplitude analytics | POST |
| `https://1.1.1.1/cdn-cgi/trace` | IP address detection (Cloudflare) | GET |
| `https://captive.apple.com/` | Connectivity check | GET |
| `https://split-tool.com/api/application-experiment/bulk-group/` | A/B test configuration | POST |
| `https://account.veepn.com/*` | User account management | Various |
| `https://order.veepn.com/*` | Subscription/pricing pages | Browser navigation |

## Data Flow Summary

1. **On Install:** Extension generates UDID, stores in chrome.storage. Opens consent-settings page asking for analytics permission. Launches free API to get access token. Enumerates all installed extensions and reports to AWS Kinesis.
2. **On Connect:** Fetches server list from API (antpeak.com or zorvian.com). Configures PAC script proxy via `chrome.proxy.settings`. Verifies connectivity via captive portal check. Updates IP via Cloudflare trace. Sends connection analytics.
3. **Content Scripts:** Two content scripts inject on all HTTP/HTTPS pages (excluding veepn.com): one shows intro offer promotional popup, another shows lock screen premium upgrade banner. Both use Shadow DOM web components. No page data is read or exfiltrated.
4. **Analytics:** Three parallel analytics pipelines (GA4, Kinesis, Amplitude) track: connection events, UI interactions, session data, installed extensions, A/B test groups. User consent is requested on first install.
5. **Proxy Architecture:** Standard PAC script proxy with exclusion list support, WebRTC leak protection, and auto-connect. Credentials are stored in chrome.storage. No residential proxy infrastructure detected.
6. **Remote Config:** Fetches remote banner configurations (Telegram channel promo) from API. Validated against strict Zod schemas. No remote code execution capability.

## Overall Risk Assessment

**Risk Level: CLEAN**

**Rationale:** VeePN is a legitimate commercial VPN extension that behaves consistently with its stated purpose. The permissions (proxy, tabs, cookies, webRequest, management, privacy, storage, `<all_urls>`) are all justified for VPN functionality. Key findings:

- **No malware indicators:** No remote code execution, no XHR/fetch hooking, no keylogging, no form interception, no credential harvesting, no ad injection, no coupon injection.
- **No residential proxy infrastructure:** The extension connects users to VeePN's own server infrastructure, not routing other users' traffic through the user's device.
- **Extension enumeration is a privacy concern but not malicious:** The data goes to VeePN's own analytics (Kinesis) for competitive intelligence. This is a common practice in the VPN industry.
- **Content script injection is promotional only:** The overlays are self-contained UI elements for upselling premium plans. No interaction with page content.
- **Analytics are extensive but consented:** The extension asks for analytics consent on first install and the data collected is standard product telemetry.
- **Code is well-structured and uses modern patterns:** Built with Vite, React, Zod validation, i18next. No obfuscation beyond standard minification.
