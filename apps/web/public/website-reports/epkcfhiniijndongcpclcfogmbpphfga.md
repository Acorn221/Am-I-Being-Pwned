# Security Analysis Report: StreamTube Proxy

## Extension Metadata

- **Extension ID**: epkcfhiniijndongcpclcfogmbpphfga
- **Name**: StreamTube Proxy
- **Version**: 3.1
- **User Count**: ~70,000
- **Analysis Date**: 2026-02-08

## Executive Summary

StreamTube Proxy is a YouTube unblocking extension primarily targeting Russian-speaking users. The extension routes YouTube traffic through proxy servers to bypass regional restrictions. While it serves its stated purpose of unblocking YouTube content, it exhibits concerning behaviors including remote configuration loading from GitHub, upselling through content injection, and telemetry collection without clear disclosure.

**Overall Risk Level: MEDIUM**

The extension functions as advertised (proxy for YouTube), but contains remote configuration capabilities and aggressive upselling mechanisms that warrant user awareness.

## Manifest Analysis

### Permissions
- `proxy` - Required for core functionality (YouTube unblocking)
- `storage` - User preferences and connection state

### Host Permissions
- `https://www.youtube.com/*` - Content injection for upselling GEMERA VPN

### Content Security Policy
No custom CSP defined (uses Manifest V3 defaults).

## Vulnerability Details

### 1. Remote Configuration Loading (MEDIUM SEVERITY)

**Severity**: MEDIUM
**Category**: Remote Code Configuration
**Files**: `background.js` (lines 90-140)

**Description**:
The extension loads configuration from a remote GitHub repository at runtime:

```javascript
fetch("https://raw.githubusercontent.com/vpn-naruzhu/public/main/uboost-extension")
  .then((r => r.json()))
  .then((o => {
    const a = o.apiBaseUrl;
    // Uses apiBaseUrl to fetch proxy configuration
    fetch(`https://${a}/api/v1/get-proxy`, {
      method: "POST",
      headers: {
        "Content-Type": "application/json"
      },
      body: JSON.stringify({
        device_id: r || "unknown",
        device_ip: o || "unknown"
      })
    })
```

**Risk**:
- The developer can change proxy servers dynamically
- The remote config endpoint could be compromised
- No integrity checks on the remote configuration
- Could potentially redirect traffic to malicious proxies

**Verdict**: This pattern is common in proxy/VPN extensions for updating server lists, but presents a trust issue. Users must trust the developer maintains secure control of the GitHub repository and backend API.

### 2. User Telemetry Collection (LOW SEVERITY)

**Severity**: LOW
**Category**: Privacy/Tracking
**Files**: `background.js` (lines 96-105, 128-137)

**Description**:
The extension collects and transmits user data to backend servers:

- Device ID (generated UUID stored locally)
- Public IP address (via api.ipify.org)
- Connection count tracking

```javascript
fetch("https://api.ipify.org?format=json").then((r => r.json())).then((r => {
  o(r.ip)
}))

fetch(`https://${a}/api/v1/get-proxy`, {
  method: "POST",
  body: JSON.stringify({
    device_id: r || "unknown",
    device_ip: o || "unknown"
  })
})
```

**Risk**:
- IP addresses and device fingerprinting enable user tracking
- Data sent to third-party API (api.ipify.org)
- No clear privacy policy disclosure in extension

**Verdict**: Standard telemetry for a proxy service (needed to allocate servers), but lacks transparency about data retention and usage.

### 3. Content Injection Upselling (LOW SEVERITY)

**Severity**: LOW
**Category**: Content Manipulation
**Files**: `content_scripts/content.js` (lines 5-14)

**Description**:
The extension injects promotional content directly into YouTube pages advertising GEMERA VPN:

```javascript
e.insertAdjacentHTML("afterbegin", `
  <div class="premium premium--animated premium--gradient">
    <div class="premium__container">
      <div class="premium__header">
        <div class="premium__message">
          <span class="premium__highlight">GEMERA VPN</span>
        </div>
        <div class="premium__actions">
          <a class="premium__button" target="_blank"
             href="https://t.me/gemera_vpn_bot?start=ytboost">
            Получить
          </a>
        </div>
      </div>
```

Injection occurs 5 seconds after page load on YouTube watch pages.

**Risk**:
- Modifies user's web experience without clear opt-out
- Could be perceived as deceptive
- Promotes external Telegram bot

**Verdict**: Aggressive monetization strategy, but not malicious. Extension clearly serves its core purpose of unblocking YouTube, and the upsell is visually obvious to users.

## API Endpoints Contacted

| Endpoint | Purpose | Risk Level |
|----------|---------|------------|
| `raw.githubusercontent.com/vpn-naruzhu/public/main/uboost-extension` | Remote config loading | MEDIUM |
| `api.ipify.org` | Public IP detection | LOW |
| `https://<dynamic>/api/v1/get-proxy` | Proxy server allocation | MEDIUM |
| `t.me/gemera_vpn_bot` | Telegram upsell | LOW |
| `forms.gle/t779oNyQqQtb6eMs8` | User ratings | LOW |
| `gemera-vpn.com` | Uninstall redirect | LOW |
| `swaponline.notion.site/YouTube-Booster-*` | Welcome page | LOW |

## Hardcoded Proxy Servers

The extension includes 5 hardcoded proxy server configurations:

- **Server 1**: `92.255.105.69:57331` (YouTube), `45.12.142.143:64322` (Google Play)
- **Server 2**: `185.103.200.141:63897` (YouTube + streaming services)
- **Server 3**: Dynamic allocation via API
- **Server 4**: `185.103.200.141:63897` with extensive domain blocklist
- **Server 5**: Similar configuration to Server 4

The extensive blocklist in servers 4 and 5 includes thousands of domains, primarily Russian sites, suggesting the extension is designed for users in Russia/CIS countries.

## Data Flow Summary

1. **On Installation**: Opens welcome page on Notion
2. **On Initialization**:
   - Generates device ID (stored locally)
   - Fetches public IP from api.ipify.org
   - Loads remote config from GitHub
   - Fetches proxy server allocation from backend
3. **On Connection**:
   - Sets PAC script with proxy rules
   - Reloads active YouTube tabs
   - Increments connection counter
4. **Content Injection**:
   - Injects GEMERA VPN promotional banner on YouTube watch pages after 5 seconds
5. **On Uninstall**: Redirects to gemera-vpn.com

## False Positive Analysis

| Pattern | Context | Verdict |
|---------|---------|---------|
| Device ID generation | UUID for server allocation | BENIGN - Standard practice |
| IP collection | Needed for proxy allocation | BENIGN - Functional requirement |
| Proxy server switching | Core feature | BENIGN - Expected functionality |
| YouTube tab reloading | Ensures proxy applies | BENIGN - User experience |
| Connection counting | Usage metrics | BENIGN - Basic analytics |

## Security Concerns

1. **Remote Configuration Trust**: Users must trust the developer maintains security of the GitHub repository and backend infrastructure.

2. **No Code Signing for Remote Config**: The dynamically loaded configuration from GitHub has no integrity verification beyond HTTPS.

3. **Broad Traffic Interception**: As a proxy extension, all YouTube traffic flows through third-party servers with unknown logging policies.

4. **Privacy Policy Absence**: No visible privacy policy regarding data collection and retention.

## Positive Security Observations

1. **Manifest V3**: Uses modern, more secure manifest version
2. **Minimal Permissions**: Only requests necessary permissions
3. **No Dynamic Code Execution**: No eval(), Function(), or similar dangerous patterns
4. **No Cookie Harvesting**: Does not access user cookies
5. **No Keylogging**: No keyboard event listeners
6. **No Extension Enumeration**: Does not detect or interfere with other extensions
7. **Transparent Functionality**: Extension does what it claims (unblock YouTube)

## Recommendations

### For Users:
1. Understand all YouTube traffic flows through third-party proxies
2. Be aware of device ID and IP tracking
3. Consider privacy implications of using free proxy services
4. Recognize the promotional content injection is part of the free service model

### For Developers:
1. Add integrity checks (signatures) for remote configuration
2. Include a clear privacy policy explaining data collection
3. Provide opt-out for promotional content injection
4. Consider certificate pinning for backend API
5. Publish transparency reports on data retention

## Overall Risk Assessment

**Risk Level: MEDIUM**

**Justification**:
StreamTube Proxy functions as advertised and provides legitimate YouTube unblocking functionality. The extension does not exhibit clearly malicious behavior such as credential theft, malware distribution, or covert surveillance. However, the remote configuration loading and telemetry collection without clear privacy disclosures represent moderate privacy and security concerns.

The extension is invasive in its upselling strategy but transparent about it (the promotional content is visible and obvious). For users who need YouTube unblocking in restricted regions and understand the trade-offs of free proxy services, this extension serves its purpose.

**Primary Concerns:**
- Remote configuration could be weaponized if developer's infrastructure is compromised
- Privacy implications of IP/device tracking unclear
- No transparency regarding proxy server logging policies

**Mitigating Factors:**
- No evidence of credential theft or malware
- No sophisticated obfuscation
- Core functionality works as described
- Relatively modest user base suggests limited attack surface value
