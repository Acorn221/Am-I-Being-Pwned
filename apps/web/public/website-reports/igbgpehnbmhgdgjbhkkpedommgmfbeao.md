# Security Analysis Report: FortiClient Chromebook Webfilter Extension

## Extension Metadata
- **Extension ID**: igbgpehnbmhgdgjbhkkpedommgmfbeao
- **Name**: FortiClient Chromebook Webfilter Extension
- **Version**: 2.0.0.0015
- **Manifest Version**: 3
- **User Count**: ~100,000
- **Publisher**: Fortinet (Enterprise Security Vendor)

## Executive Summary

The FortiClient Chromebook Webfilter Extension is a **legitimate enterprise security product** designed for organizational web content filtering and monitoring. However, it collects extensive browsing data and user information, transmitting it to both Fortinet's FortiGuard rating service and customer-configured management servers (EMS/FAZ).

**Risk Level: MEDIUM**

The extension operates as intended for its enterprise use case, but the scope of data collection raises privacy concerns for individual users who may not be fully aware of the monitoring capabilities.

## Vulnerability & Privacy Findings

### 1. MEDIUM: Comprehensive Browsing Activity Logging

**Location**: `service_worker.js` lines 4997-5056

**Description**: The extension logs detailed information about every web request, including:
- Full URLs with query parameters (`url: n.pathname + n.search`)
- User email addresses (`user: this.bus.profileManager.getEmail()`)
- Source IP addresses (`srcip: this.bus.profileManager.getIpAddr()`)
- Timestamps (UTC date/time)
- Hostname and port information
- User-initiated vs. automatic request classification

**Code Evidence**:
```javascript
makeLogUrlInfo(e, t, r) {
  const n = new URL(e.url),
    i = n.protocol.slice(0, -1);
  return {
    dstport: "https" === i ? 443 : 80,
    remotename: n.hostname,
    service: i,
    url: n.pathname + n.search,
    threat: t,
    userinitiated: Number(e.type === chrome.webRequest.ResourceType.MAIN_FRAME),
    utmaction: et.getUTMAction(r)
  }
}
```

**Impact**: Complete browsing history is captured and transmitted to external servers. Users have no control over this data collection beyond uninstalling the extension.

### 2. MEDIUM: Multiple External Data Transmission Endpoints

**Location**: `service_worker.js` lines 4264-4313

**Description**: The extension transmits collected data to multiple external endpoints:

1. **EMS (Enterprise Management Server)**: Customer-configured endpoint for logs, stats, and word filtering data
2. **FAZ (FortiAnalyzer)**: Fortinet's log aggregation system with LZ4 compression
3. **FortiGuard Rating Service**: `wsfgd1.fortiguard.net:3400` for URL categorization

**Code Evidence**:
```javascript
async sendEMSLogs(e) {
  const t = await this.emsAPI(a.Post, i.Log,
    this.bus.profileManager.getEmsUrl(),
    this.bus.profileManager.getUserId(),
    this.bus.profileManager.getSiteName(),
    JSON.stringify(e), {
      "Content-Type": "application/json"
    });
  // ... sends logs to customer EMS server
}

async sendFAZLogs(e, t) {
  const r = { "Content-Type": "application/json" };
  t && (r["Content-Encoding"] = "lz4");
  const n = await Ue(this.bus.profileManager.getFAZServer(), Re.FAZ, {
    method: a.Post,
    headers: r,
    body: e
  });
  // ... sends to FAZ endpoint
}
```

**Impact**: Browsing data is transmitted to multiple third parties, potentially stored indefinitely on enterprise servers outside user control.

### 3. MEDIUM: Device Fingerprinting via WebRTC

**Location**: `offscreen.js` lines 151-193

**Description**: The extension uses WebRTC ICE candidate gathering to extract the user's local IP address, which is then included in transmitted logs.

**Code Evidence**:
```javascript
async getIpFromWebRTC(e) {
  try {
    const t = new RTCPeerConnection({ iceServers: [] });
    t.createDataChannel("");
    const o = await t.createOffer();
    await t.setLocalDescription(o);
    e(await new Promise((e => {
      // ... extracts IP from ICE candidates
      const i = /((?:\d{1,3}\.){3}\d{1,3})|((?:[a-fA-F0-9]{1,4}:){7}[a-fA-F0-9]{1,4})/.exec(a);
      // ... returns IP address
    })))
  }
}
```

**Impact**: Local network IP address is exposed and transmitted, enabling device tracking across network changes.

## Network Endpoints

The extension communicates with the following external domains:

1. **wsfgd1.fortiguard.net:3400** - FortiGuard URL rating service for content categorization
2. **cloud-controller.forticlient.com** - Cloud authentication and token management
3. **Customer-configured EMS server** - Enterprise management endpoint (configured via managed policy)
4. **Customer-configured FAZ server** - Log aggregation endpoint (configured via managed policy)

## Permissions Analysis

The extension declares the following sensitive permissions:

- **`<all_urls>`**: Full access to all websites
- **`webRequest`** + **`webRequestBlocking`**: Intercept and block network requests
- **`tabs`**: Access to all tab information
- **`storage`** + **`unlimitedStorage`**: Persistent data storage
- **`identity`** + **`identity.email`**: Access to user's Chrome profile email
- **`privacy`**: Modify browser privacy settings (safe search enforcement)
- **`webNavigation`**: Monitor navigation events
- **`offscreen`**: Background execution for WebRTC IP detection

All permissions are justified for the extension's stated purpose of web filtering and monitoring.

## Data Flow Summary

1. User navigates to a website
2. Content script + service worker intercept the request
3. URL is sent to FortiGuard for categorization
4. Based on policy (retrieved from EMS), the request is allowed/blocked/warned
5. Log entry is created containing:
   - URL + query parameters
   - User email (from Chrome identity API)
   - Source IP (from WebRTC)
   - Timestamp, hostname, protocol
   - Category rating from FortiGuard
6. Logs are batch-transmitted to EMS and/or FAZ servers
7. Statistics on blocked categories are also transmitted

## Security Positives

- No malicious code execution
- No data exfiltration to unauthorized parties
- Legitimate enterprise use case
- Encrypted local storage using AES-GCM with PBKDF2-derived keys
- Proper error handling and timeout mechanisms
- No eval() or Function() constructor usage
- No remote code loading

## Configuration Mechanism

The extension is designed for enterprise deployment via Chrome's **Managed Storage** feature:

**Schema** (`schema.json`):
```json
{
  "ProfileServerUrl": "string",
  "AuthServerUrl": "string",
  "RatingServerUrl": "string",
  "InvitationCode": "string",
  "SerialNumber": "string",
  "SiteName": "string"
}
```

These values are intended to be set by IT administrators via group policy, not by end users.

## Recommendations

### For Organizations:
1. **Disclose monitoring scope** to employees during onboarding
2. **Configure appropriate retention policies** on EMS/FAZ servers
3. **Review logged data access controls** to prevent unauthorized viewing
4. **Consider excluding certain URLs** (e.g., health/financial sites) from logging

### For Individual Users:
1. **Do not install** unless required by your employer/school
2. **Assume all browsing activity is logged** if extension is present
3. **Use personal devices** for privacy-sensitive browsing
4. **Check extension list regularly** (`chrome://extensions`) for unexpected installations

## Final Verdict

**Risk Level: MEDIUM**

This is a **legitimate enterprise security product** functioning as designed. The privacy risks are inherent to its purpose as a web filtering and monitoring solution. Organizations deploying this extension should ensure transparency with users about the scope of monitoring.

**Not Malware** - but extensive data collection warrants clear user disclosure.

---

## Tags

- `privacy:extensive_logging` - Logs all URLs with timestamps and user identity
- `privacy:email_collection` - Collects Chrome profile email address
- `privacy:ip_collection` - Extracts local IP via WebRTC
- `data_flow:third_party` - Transmits to FortiGuard, EMS, and FAZ servers
