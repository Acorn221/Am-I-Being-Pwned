# Keepa - Amazon Price Tracker Security Analysis

## Extension Metadata
- **Extension Name**: Keepa™ - Amazon Price Tracker
- **Extension ID**: neebplgakaahbhdphmkckjjcegoiijjo
- **Version**: 5.58
- **User Count**: ~4,000,000
- **Author**: Keepa GmbH
- **Manifest Version**: 3

## Executive Summary

Keepa is a legitimate Amazon price tracking extension with substantial permissions and data handling capabilities. The extension operates as intended - providing price history charts and stock information for Amazon products. While it employs invasive techniques including cookie manipulation, session swapping, and real-time data transmission to Keepa servers, these behaviors serve the declared functionality and do not constitute malicious activity. The extension implements sophisticated cookie isolation to prevent user session contamination during stock checking operations.

**Overall Risk Assessment: CLEAN**

The extension requires extensive permissions and performs privacy-invasive operations, but these are necessary for its core price tracking and stock checking features. All data flows to legitimate Keepa infrastructure, and the functionality aligns with user expectations for an Amazon price tracker.

## Vulnerability Analysis

### 1. Cookie Manipulation & Session Management
**Severity**: INFO (Legitimate but invasive)
**Files**: `keepa.js` (lines 138-157, 287-304, 394-407), `manifest.json` (line 7)

**Description**:
The extension employs sophisticated cookie management to enable stock checking without contaminating the user's Amazon session:

```javascript
const swapCookies = async(a, c, b) => {
  cloud.getSessionId(c);
  cloud.getSessionId(b);
  let f = null != b ? new Set(b.map(g => g.name)) : null, d = [];
  if (null != c) {
    for (let g of c) {
      null != b && f.has(g.name) || (delete g.hostOnly, delete g.session,
        d.push(chrome.cookies.remove({url:a + g.path, name:g.name})));
    }
  }
  if (null != b) {
    for (let g of b) {
      delete g.hostOnly, delete g.session, g.url = a,
        d.push(chrome.cookies.set(g));
    }
  }
  await Promise.all(d).catch(g => {
    setTimeout(() => {
      common.reportBug(g, "Error in cookie swap.");
    }, 1);
  });
}
```

The extension:
- Swaps between user cookies and extension-managed "guest" cookies
- Maintains separate session IDs to prevent session contamination
- Stores compressed cookie data in `chrome.storage.local`
- Restores user cookies after stock operations complete

**Verdict**: This is invasive but serves the legitimate purpose of checking stock availability without affecting the user's cart or session. The implementation includes safeguards to prevent session collision.

---

### 2. Persistent WebSocket Connection to Keepa Servers
**Severity**: INFO (Privacy-invasive but expected)
**Files**: `keepa.js` (lines 1156-1221)

**Description**:
Maintains a persistent WebSocket connection to `wss://dyn.keepa.com/apps/cloud/`:

```javascript
const f = "wss://dyn.keepa.com/apps/cloud/?app=" + type + "&version=" +
  common.version + "&i=" + installTimestamp + "&mf=3&optOut=" + a +
  "&time=" + Date.now() + "&id=" + chrome.runtime.id + "&wr=" +
  (hasWebRequestPermission ? 1 : 0) + "&offscreen=" +
  (offscreenSupported ? 1 : 0) + "&mobile=" + isMobile;
const d = new WebSocket(f, settings.token);
```

Connection includes:
- Extension version, installation timestamp, runtime ID
- User token (64-character identifier)
- WebRequest permission status
- Compressed data transmission using `DecompressionStream`

**Data Transmitted**:
- ASIN (Amazon product identifiers) from viewed pages
- User browsing activity on Amazon (product views, listings)
- Stock checking results
- Extension telemetry

**Verdict**: Expected behavior for a cloud-based price tracking service. Users should be aware all Amazon browsing is transmitted to Keepa servers. Privacy policy compliance not evaluated.

---

### 3. Stock Availability Checking via Cart Manipulation
**Severity**: INFO (Invasive but disclosed)
**Files**: `keepa.js` (lines 831-972), `offscreen.js` (lines 232-344)

**Description**:
The extension implements multiple strategies to determine exact stock levels:

**Method 1: Add-to-Cart AJAX** (offscreen disabled or batch mode):
```javascript
h.fetch.body = h.fetch.body.replaceAll("{SESSION_ID}", g)
  .replaceAll("{CSRF}", encodeURIComponent(a.csrf))
  .replaceAll("{OFFER_ID}", a.oid)
  .replaceAll("{ADDCART}", encodeURIComponent(common.stockData.stockAdd[a.domainId]))
  .replaceAll("{ASIN}", a.asin);
```

**Method 2: Create Cart + Add-to-Cart Association**:
- Creates temporary cart using Amazon's API
- Extracts CSRF tokens from HTML responses
- Adds items to cart with maximum quantity
- Parses cart HTML to extract actual stock levels
- Caches results in extension storage

**Techniques**:
- Session isolation via cookie swapping
- CSRF token extraction from multiple sources
- Cart creation and item addition
- Seller ID verification and matching
- Batch processing for efficiency

**Verdict**: Legitimate functionality for a stock tracking tool. The extension properly isolates these operations from the user's actual shopping session through the cookie swap mechanism.

---

### 4. Comprehensive Amazon Activity Monitoring
**Severity**: INFO (Expected for functionality)
**Files**: `content.js` (lines 1092-1247, 252-269)

**Description**:
The extension monitors extensive Amazon user activity:

**Tracked Events**:
- All product page visits across 14 Amazon domains
- Search results and bestseller pages
- Seller central and affiliate portal visits
- Product variation selections (color, size changes)
- Mouse movement, keyboard input, touch events on seller pages

**Data Collection**:
```javascript
chrome.runtime.sendMessage({type:"sendData", val:{
  key:"f1",
  payload:[/* product data */]
}}, function() {});
```

**Scraped Product Data**:
- ASINs from all visible products
- Prices, seller information
- Stock availability indicators
- Rating counts and review data

**Verdict**: Necessary for price tracking functionality. Users should understand their entire Amazon browsing history is monitored and transmitted.

---

### 5. DOM Manipulation & HTML Injection
**Severity**: LOW (Controlled injection)
**Files**: `content.js` (lines 379-658)

**Description**:
The extension injects multiple UI elements:

1. **Price graphs** via iframe embedding (`https://keepa.com/keepaBox.html`)
2. **Stock indicators** with live updates
3. **MAP (Minimum Advertised Price) reveal** for hidden prices

**Injection Methods**:
```javascript
e.setAttribute("id", "keepaContainer");
k.setAttribute("src", "https://keepa.com/keepaBox.html");
k.setAttribute("scrolling", "no");
k.setAttribute("id", "keepa");
```

All injected content originates from official Keepa domains. No third-party CDNs or untrusted sources detected.

**Verdict**: CLEAN - Controlled injection from trusted sources.

---

### 6. Automated Request Generation
**Severity**: INFO (Rate-limited)
**Files**: `keepa.js` (lines 226-386, 787-799)

**Description**:
Request queue with automatic retry and batching:

```javascript
const requestQueue = new AutoQueue();
const processRequest = async a => {
  lastActivity = Date.now();
  // Process queued requests
};
```

**Features**:
- Sequential and batch processing modes
- Timeout handling (408 errors after 5-16 seconds)
- Rate limiting via `sellerLockoutDuration` (60 seconds)
- Retry logic with exponential backoff

**Verdict**: Properly rate-limited to avoid Amazon abuse detection.

---

## Permissions Analysis

| Permission | Usage | Risk Level |
|------------|-------|------------|
| `alarms` | Keep-alive mechanism to prevent service worker termination | LOW |
| `storage` | Store cookies, settings, tokens, compressed data | MEDIUM |
| `declarativeNetRequestWithHostAccess` | Modify request headers (Cookie, Origin, CSRF tokens) | HIGH |
| `cookies` | Read/write Amazon and Keepa cookies | HIGH |
| `contextMenus` | "View products on Keepa" context menu | LOW |
| `offscreen` | Parse HTML in background for stock extraction | MEDIUM |
| `webRequest` | Intercept Set-Cookie headers for session management | HIGH |

**Host Permissions**:
- `*://*.keepa.com/*` - Own infrastructure
- `*://*.amazon.*/*` (14 domains) - Required for price tracking
- `*://*.amzn.com/*` - Amazon short URLs

---

## API Endpoints & Data Flow

| Endpoint | Purpose | Data Transmitted |
|----------|---------|------------------|
| `wss://dyn.keepa.com/apps/cloud/` | Real-time data sync | ASINs, browsing activity, stock data, telemetry |
| `https://dyn-2.keepa.com/service/bugreport/` | Error reporting | Stack traces, extension state, error details |
| `https://dyn-2.keepa.com/app/stats/` | Uninstall tracking | Extension version, uninstall event |
| `https://graph.keepa.com/pricehistory.png` | Price graph images | ASIN, domain, graph dimensions |
| `https://keepa.com/keepaBox.html` | Iframe UI container | Product details, user token |

**Data Compression**: All WebSocket traffic uses Deflate compression.

---

## False Positives

| Detection | Explanation | Verdict |
|-----------|-------------|---------|
| Cookie manipulation | Required for stock checking without session contamination | FALSE POSITIVE |
| Session swapping | Isolates extension operations from user account | FALSE POSITIVE |
| Request header modification | Necessary for CSRF token injection in stock checks | FALSE POSITIVE |
| Amazon activity monitoring | Core functionality of price tracker | FALSE POSITIVE |
| WebSocket telemetry | Expected cloud-based service behavior | FALSE POSITIVE |

---

## Privacy Considerations

**Data Collected**:
1. All Amazon product views across 14 domains
2. Search queries and browsing patterns
3. Seller page activity (including mouse/keyboard events)
4. Installation timestamp and extension ID
5. Stock checking results and cached cart data

**Data Storage**:
- Local: Compressed cookies, settings, tokens
- Remote: Transmitted to Keepa servers via WebSocket

**User Control**:
- `optOut_crawl` setting available (not default)
- No malicious exfiltration detected
- All data flows to declared Keepa infrastructure

---

## Security Strengths

1. **No eval() or dynamic code execution** - All code is static
2. **No third-party dependencies** - Pure extension code
3. **Proper CSRF protection** - Extracts and uses Amazon CSRF tokens
4. **Session isolation** - Cookie swapping prevents user session contamination
5. **Error handling** - Bug reporting with stack traces (aids debugging)
6. **Rate limiting** - Prevents Amazon API abuse

---

## Overall Risk Assessment

**Risk Level**: **CLEAN**

**Justification**:
While Keepa employs invasive techniques including cookie manipulation, session management, and comprehensive Amazon activity monitoring, these behaviors are:

1. **Necessary** for the declared functionality (price tracking and stock checking)
2. **Properly implemented** with session isolation safeguards
3. **Expected** by users installing an Amazon price tracker
4. **Transparent** in data flow to Keepa infrastructure

The extension does not:
- Inject ads or affiliate links
- Redirect to malicious sites
- Exfiltrate credentials or payment data
- Perform hidden cryptocurrency mining
- Execute arbitrary remote code
- Manipulate Amazon transactions without user knowledge

**Recommendation**: CLEAN with privacy disclosure. Users should be aware that all Amazon browsing activity is transmitted to Keepa servers for price history analysis. The extensive permissions are required for legitimate functionality.

---

## Report Metadata
- **Analysis Date**: 2026-02-08
- **Analyst**: Security Research Agent
- **Analysis Duration**: Comprehensive (3472 lines of code reviewed)
- **Tools Used**: Manual code review, pattern matching, data flow analysis
