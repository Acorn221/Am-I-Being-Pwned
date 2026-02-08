# Bunny VPN Security Analysis Report

## Extension Metadata

- **Extension ID**: lklimgabcbcgnpdmhcgeomcpigimjdfe
- **Name**: Bunny VPN
- **Version**: 1.7.2
- **Users**: ~20,000
- **Rating**: 3.8/5
- **Language**: Russian
- **Manifest Version**: 3

## Executive Summary

Bunny VPN is a Russian-language Chrome extension providing HTTP proxy-based VPN functionality through hardcoded proxy servers. The extension implements a freemium model with a subscription system backed by a single unencrypted HTTP API endpoint. While the extension serves its intended purpose as a proxy service, it exhibits **multiple security and privacy concerns** including insecure communication channels, hardcoded API keys, and potential for third-party backend compromise.

**Overall Risk Level: MEDIUM**

The extension functions as advertised (proxy/VPN service) but has architectural security flaws that could expose users to privacy risks if the backend infrastructure is compromised.

## Vulnerability Details

### 1. INSECURE BACKEND COMMUNICATION (HIGH SEVERITY)

**Files**: `background.js`, `account.js`, `payment.js`

**Description**: All backend API communication occurs over **unencrypted HTTP** (not HTTPS), exposing sensitive user data in transit.

**Affected Endpoints**:
```javascript
const BACKEND_URL = 'http://217.12.38.98:3000';  // Unencrypted!
const API_KEY = '249d9686912fc2f1887aef7893f242755aad5ddea071ddf1d151517a843dc84c';
```

**Exposed Data**:
- Account IDs (format: `ACC-[timestamp][random]`)
- Subscription status and expiry dates
- Payment transaction IDs
- Telegram user IDs for bonus verification
- Server load metrics

**API Endpoints**:
- `/api/server-load` - Server health metrics
- `/api/subscription/{accountId}` - Subscription status
- `/api/telegram/bonus-status/{accountId}` - Telegram bonus verification
- `/api/telegram/check-subscription` - Telegram channel subscription verification
- `/api/promocode/activate` - Promocode activation
- `/api/create-payment` - Payment creation (includes account ID)
- `/api/payment-status/{transactionId}` - Payment status polling

**Code Evidence** (`payment.js:605-617`):
```javascript
const resp = await fetch(`${BACKEND_URL}/api/create-payment`, {
  method: 'POST',
  headers: {
    'Content-Type': 'application/json',
    'X-API-Key': API_KEY  // Exposed in plaintext
  },
  body: JSON.stringify({
    amount,
    accountId,  // User identifier sent over HTTP
    description,
    method: paymentMethod
  })
});
```

**Impact**:
- User account IDs can be intercepted via network sniffing
- Subscription status can be tracked
- Payment activities visible to network observers (ISP, WiFi administrators, MitM attackers)
- API key can be stolen and abused

**Verdict**: **VULNERABLE** - Using HTTP for backend communication is a critical flaw. All data is transmitted in cleartext.

---

### 2. HARDCODED API KEY EXPOSURE (MEDIUM SEVERITY)

**Files**: `background.js:50`, `account.js:29`, `payment.js:3`

**Description**: The backend API key is hardcoded in multiple JavaScript files, making it trivially extractable by any user.

```javascript
const API_KEY = '249d9686912fc2f1887aef7893f242755aad5ddea071ddf1d151517a843dc84c';
```

**Impact**:
- Anyone can extract the API key from the extension
- Attackers can directly access backend APIs
- No rate limiting or user-specific authentication
- Potential for backend abuse (fake subscriptions, load manipulation)

**Verdict**: **VULNERABLE** - API key in client-side code provides no real security.

---

### 3. PROXY SERVER INFRASTRUCTURE (LOW-MEDIUM SEVERITY)

**Files**: `background.js:32-43`

**Description**: Extension routes all user traffic through hardcoded HTTP proxy servers.

**Hardcoded Servers**:
```javascript
const servers = {
  frankfurt: { scheme: 'http', host: '94.177.58.26', port: 7443 },
  frankfurt_backup: { scheme: 'http', host: '138.124.53.25', port: 7443 },
  netherlands_free: { scheme: 'http', host: '94.176.3.109', port: 7443 },
  test: { scheme: 'http', host: '94.176.3.43', port: 7443 },
  netherlands_backup_2: { scheme: 'http', host: '94.176.3.110', port: 7443 },
  netherlands: { scheme: 'http', host: '94.176.3.42', port: 7443 },
  berlin: { scheme: 'http', host: '45.134.217.191', port: 7443 },
  latvia: { scheme: 'http', host: '2.58.98.155', port: 7443 },
  finland: { scheme: 'http', host: '85.192.61.93', port: 7443 },
  turkey: { scheme: 'http', host: '45.89.52.240', port: 7443 }
};
```

**Privacy Concerns**:
- All user HTTPS traffic flows through these proxy servers
- Proxy operators have visibility into browsing patterns
- HTTP traffic can be read/modified by proxy operators
- No independent verification of proxy server trustworthiness
- Proxy servers can log all requests

**Verdict**: **BY DESIGN** - This is the intended functionality of a VPN/proxy extension. Users must trust the operator. However, the lack of transparency about data handling policies is concerning.

---

### 4. WEBRTC IP LEAK PROTECTION (POSITIVE CONTROL)

**Files**: `background.js:5`

**Description**: Extension properly protects against WebRTC IP leaks.

```javascript
chrome.privacy.network.webRTCIPHandlingPolicy.set({
  value: 'disable_non_proxied_udp'
});
```

**Verdict**: **SECURE** - Proper implementation of WebRTC leak protection.

---

### 5. CONTENT SCRIPT FUNCTIONALITY (LOW SEVERITY)

**Files**: `content-script.js`, `minibar.js`, `time-overlay.js`

**Description**: Content scripts injected on all pages with opt-in features:

**content-script.js** (Volume Control):
- Monitors all `<video>` and `<audio>` elements
- Overrides volume settings via `volumechange` event listener
- Uses MutationObserver to track new media elements
- Stores volume preference in chrome.storage.local

**minibar.js** (VPN Toggle Widget):
- Injects a floating VPN status widget on all pages (opt-in, disabled by default)
- Allows toggling VPN from any page
- Uses backdrop-filter CSS (high z-index: 2147483646)

**time-overlay.js** (Moscow Time Display):
- Displays Moscow time overlay on pages (opt-in)
- Updates every second via setInterval

**Verdict**: **LOW RISK** - Features are opt-in and serve legitimate purposes. Volume control is slightly invasive but benign.

---

### 6. TELEGRAM INTEGRATION & BONUS SYSTEM (LOW SEVERITY)

**Files**: `account.js:56-344`

**Description**: Extension offers 2-day premium trial for subscribing to Telegram channel `@vpnbunnyy`.

**Verification Flow**:
1. User subscribes to Telegram channel
2. User obtains Telegram ID from `@userinfobot`
3. User enters Telegram ID in extension
4. Extension sends verification request to backend:

```javascript
const resp = await fetch(`${BACKEND_URL}/api/telegram/check-subscription`, {
  method: 'POST',
  body: JSON.stringify({
    accountId: accountId,
    telegramUserId: telegramUserId  // User-provided Telegram ID
  })
});
```

**Security Issues**:
- Relies on backend verification (via Telegram Bot API)
- User can claim bonus once per account and once per Telegram ID
- Backend must be trusted to properly verify subscriptions

**Verdict**: **LOW RISK** - Promotional feature. Backend dependency for verification.

---

### 7. PAYMENT INTEGRATION (MEDIUM SEVERITY)

**Files**: `payment.js`

**Description**: Extension integrates with payment provider "Platega" for subscription purchases.

**Payment Flow**:
```javascript
const resp = await fetch(`${BACKEND_URL}/api/create-payment`, {
  method: 'POST',
  body: JSON.stringify({
    amount,           // e.g., 199 rubles
    accountId,        // User's account ID
    description,      // "VPN Bunny - 30 дней"
    method: paymentMethod  // 'card' or 'sbp'
  })
});
// Returns: { redirect: "https://...", transactionId: "..." }
chrome.tabs.create({ url: data.redirect });
```

**Concerns**:
- Payment processing happens on backend (unencrypted HTTP)
- Extension polls for payment status every 5 seconds for 15 minutes
- Account ID linked to payments (potential for user tracking)
- No client-side payment validation

**Verdict**: **MEDIUM RISK** - Payment data exposed via HTTP. Backend security critical.

---

## False Positives

| Pattern | Location | Reason |
|---------|----------|--------|
| `innerHTML` assignments | Multiple UI files | Safe - building DOM from static strings or sanitized variables, no user input |
| `chrome.tabs.create` | payment.js, account.js | Legitimate - opening payment pages and Telegram links |
| Fetch to `2ip.ua` | Host permissions | Likely for IP detection (common for VPN extensions) |
| Volume control hooks | content-script.js | Opt-in feature for controlling media volume across tabs |

---

## API Endpoints Table

| Endpoint | Method | Purpose | Data Sent | Risk |
|----------|--------|---------|-----------|------|
| `http://217.12.38.98:3000/api/server-load` | GET | Load balancer metrics | API key | HIGH - Unencrypted |
| `http://217.12.38.98:3000/api/subscription/{id}` | GET | Check subscription | Account ID, API key | HIGH - Unencrypted |
| `http://217.12.38.98:3000/api/telegram/bonus-status/{id}` | GET | Telegram bonus status | Account ID, API key | HIGH - Unencrypted |
| `http://217.12.38.98:3000/api/telegram/check-subscription` | POST | Verify Telegram sub | Account ID, Telegram ID | HIGH - Unencrypted |
| `http://217.12.38.98:3000/api/promocode/activate` | POST | Activate promo code | Account ID, code | HIGH - Unencrypted |
| `http://217.12.38.98:3000/api/create-payment` | POST | Create payment | Account ID, amount, method | **CRITICAL** - Payment data over HTTP |
| `http://217.12.38.98:3000/api/payment-status/{txId}` | GET | Poll payment status | Transaction ID, API key | HIGH - Unencrypted |

---

## Data Flow Summary

### Collected Data:
- **Account ID**: Generated client-side (`ACC-[timestamp][random]`)
- **Selected server**: Frankfurt, Netherlands, etc.
- **Subscription status**: Active/inactive, expiry date
- **Telegram User ID**: For bonus verification (optional)
- **Payment transactions**: Amount, method, transaction ID
- **Settings**: Split tunneling rules, excluded sites, theme preference

### Data Storage:
- **chrome.storage.local**: Account credentials, subscription status, settings
- **Backend database**: Account-subscription mappings, payment records, Telegram bonuses

### Data Transmission:
- **To Backend API**: All user data sent over **unencrypted HTTP**
- **To Proxy Servers**: All browsing traffic (HTTPS remains encrypted end-to-end, HTTP visible)

---

## Additional Findings

### Load Balancing System
The extension implements sophisticated load balancing across server pools:
- Health checks every 15 seconds
- Latency-based server selection
- Automatic failover on proxy errors (threshold: 3 errors/minute)
- Server load data from backend API

**Verdict**: Well-engineered feature, but relies on insecure backend communication.

### Split Tunneling
Users can configure:
- Route all traffic through VPN (default)
- Exclude specific domains from VPN
- Route ONLY specific domains through VPN (uses PAC script)

**Verdict**: Legitimate privacy feature. Implementation appears correct.

---

## Overall Risk Assessment

**RISK LEVEL: MEDIUM**

### Summary of Findings:
- ✅ **No malicious code detected**
- ✅ **No keylogging or ad injection**
- ✅ **No extension enumeration/killing**
- ✅ **No cookie harvesting beyond normal proxy operation**
- ⚠️ **Critical**: All backend communication over HTTP (not HTTPS)
- ⚠️ **High**: Hardcoded API key can be extracted
- ⚠️ **Medium**: Payment data transmitted insecurely
- ⚠️ **Design**: Users must trust proxy operators (inherent to VPN services)

### Verdict:
**MEDIUM RISK** - The extension functions as a legitimate VPN/proxy service and does not contain malware. However, the use of **unencrypted HTTP for backend APIs** is a significant security flaw that could expose user data to network observers. The hardcoded API key provides no meaningful protection. Users should be aware that their subscription data and payment activities are transmitted in cleartext.

**Recommendation**: The extension should migrate all backend communication to HTTPS and implement proper authentication mechanisms beyond a hardcoded API key. Until these issues are resolved, privacy-conscious users should avoid this extension.
