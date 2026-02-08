# Security Analysis Report: FBA calculator for Amazon Sellers : SellerApp

## Extension Metadata
- **Extension ID**: bkdkbhjcfhfkmkbffkdklaiepfbllbgg
- **Name**: FBA calculator for Amazon Sellers : SellerApp
- **Users**: ~70,000
- **Version**: 2.9.5
- **Manifest Version**: 3

## Executive Summary

SellerApp is a legitimate Amazon seller tool that provides FBA (Fulfillment by Amazon) profit calculations. The extension contains **concerning infrastructure** for web scraping operations through a persistent WebSocket connection to SellerApp's backend. While the functionality appears aligned with the extension's stated purpose, the scraping architecture and data collection patterns present privacy concerns and potential for misuse.

**Overall Risk: MEDIUM**

## Vulnerability Details

### 1. Residential Proxy / Scraping Infrastructure
**Severity**: MEDIUM
**Files**: `background.bundle.js:20717`
**Code**:
```javascript
p = new WebSocket(`wss://scrapernet.sellerapp.com/scraper-net/websocket?id=${T}&instance_id=${f}&geo=${E}&ext_type=${e}&account_id=${t}&ip_address=${A}&zip_code=${null==y?void 0:y.zip_code}&is_user_logged_in=${b}`)
```

**Description**: The extension establishes a persistent WebSocket connection to `scrapernet.sellerapp.com` that acts as a scraping proxy. The server sends scraping jobs to the extension, which:
- Fetches arbitrary Amazon URLs on behalf of SellerApp's backend
- Parses the HTML using custom parser configurations
- Sends parsed data back through the WebSocket
- Includes user's IP address, geolocation, and login status in the connection

**Supporting Evidence** (`background.bundle.js:20745-20773`):
```javascript
const i = JSON.parse(i);
if (o.url) {
  const a = o.url,
    i = o.parser_config_url.page_type;
  // Extension fetches the URL
  (0, s.fetchDetails)(a).then((s => r(this, void 0, void 0, (function*() {
    // Parses based on page type: KEYWORD_SEARCH, PRODUCT_LISTING, SELLER_PROFILE, etc.
    "KEYWORD_SEARCH" === i ? r = yield I(s, a, o.parse_html, o.all_pages || !1, (null == o ? void 0 : o.page_limit) || 7, o.request_id)
    // ... other page types
    e.send(JSON.stringify(r)) // Sends parsed data back
  }))
}
```

**Verdict**: This is a **residential proxy infrastructure** where SellerApp uses its users' browsers to scrape Amazon at scale. While technically serving the extension's FBA calculation features, users are unknowingly participating in a distributed scraping network. This is:
- **Privacy issue**: User's IP and location used for commercial scraping
- **Terms of Service violation**: Automated scraping violates Amazon's ToS
- **Resource abuse**: Uses user bandwidth without explicit consent
- **Risk exposure**: Amazon could flag/ban user accounts for bot activity

### 2. User Session and Location Harvesting
**Severity**: MEDIUM
**Files**: `background.bundle.js:20700-20717`, `background.bundle.js:20786-20799`
**Code**:
```javascript
// Fetches user's IP and country from external service
const t = yield fetch("https://lumtest.com/myip.json"), n = yield t.json();
E = n.country, A = n.ip, (0, o.set)("country_id", E), (0, o.set)("ip_address", A)

// Checks login status across multiple Amazon marketplaces
for (const e of Object.keys(h)) {
  const r = yield(0, s.fetchDetails)(`${h[e]}/s?k=samsung`),
  a = (0, s.parse)(r, i.userLoggedInSchema),
  o = { geo: e };
  (null === (t = null == a ? void 0 : a.sign_in_button_url) || void 0 === t ? void 0 : t.includes("signin")) ?
    o.isLoggedIn = !1 : o.isLoggedIn = !0;
  const c = (0, s.parse)(r, i.zipCodeSchema);
  o.zipCode = c.zip_code, n.push(o);
}
```

**Description**: The extension actively probes:
- User's public IP address and country (via lumtest.com)
- Amazon login status across all 23+ marketplaces (US, UK, DE, JP, IN, etc.)
- User's postal/ZIP code from Amazon profile
- Sends all collected data to SellerApp's WebSocket server

**Verdict**: **Excessive data collection**. While some geo data is needed for FBA calculations, systematically checking login status across every Amazon marketplace and sending IP addresses to a third-party server exceeds legitimate functionality. This creates a profile of each user's Amazon account presence globally.

### 3. Automatic Amazon Account Manipulation (Zip Code Changes)
**Severity**: MEDIUM
**Files**: `background.bundle.js:23053-23079`, `background.bundle.js:20748-20752`
**Code**:
```javascript
// Remote command to change zip code
if (o.zipcode) {
  const e = /https?:\/\/(www\.)?([a-zA-Z0-9.-]+)/,
    t = c.default.parseUrl(a).url.match(e)[0],
    n = yield(0, s.fetchDetails)(t);
  yield(0, l.setZipCode)(n, t, o.zipcode)
}

// Implementation that POSTs to Amazon
t.setZipCode = (e, t, n) => r(void 0, void 0, void 0, (function*() {
  const r = s.load(e)("#glowValidationToken").val(),
    a = yield o(t, r);
  yield i({
    locationType: "LOCATION_INPUT",
    zipCode: n,
    deviceType: "web",
    storeContext: "home-garden",
    pageType: "Detail",
    actionSource: "glow"
  }, t, a)
}));

// POST to Amazon's address change API
yield a.default.post(`${t}/portal-migration/hz/glow/address-change?actionSource=glow`, e, {
  headers: {
    "anti-csrftoken-a2z": n
  }
})
```

**Description**: Extension can programmatically change user's Amazon delivery zip code via remote WebSocket commands without user interaction. This allows SellerApp to manipulate user Amazon accounts to obtain location-specific pricing/availability data.

**Verdict**: **Invasive account manipulation**. While potentially necessary for accurate FBA calculations across regions, this modifies user account settings without explicit per-action consent. Users are likely unaware their Amazon delivery location can be remotely changed.

### 4. External Extension Communication
**Severity**: LOW
**Files**: `manifest.json:1`, `background.bundle.js:40410-40424`
**Code**:
```javascript
// manifest.json
"externally_connectable": {
  "ids": ["lofbbfcpljahnhgncgommcbkckdbjdof"]
}

// Listens for messages from external extension
chrome.runtime.onMessageExternal.addListener((function(e, t, n) {
  "OPEN_EXTENSION" === e.message && (chrome.tabs.query({
    currentWindow: !0,
    active: !0
  }, (function(e) {
    var t = e[0];
    null !== t.url && t.id && chrome.tabs.sendMessage(t.id, {
      type: "OPEN_MODAL",
      modalType: "PROFIT_CALCULATOR"
    })
  })))
}))
```

**Description**: Extension accepts messages from another SellerApp extension (ID: lofbbfcpljahnhgncgommcbkckdbjdof) to trigger the FBA calculator modal.

**Verdict**: **Low risk cross-extension communication**. Limited to opening UI modal, no sensitive data exposure. Appears to be companion extension integration.

### 5. API Key Exposure
**Severity**: LOW
**Files**: `manifest.json:5`
**Code**:
```javascript
"key":"MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAvsRZLoyUvFoGUk18oy/50uI0cVKIXkh81OR5ekFVo9352fPJZzjCJHbK50Dv1qoqRGRxkAEnYqrTKnxmSZJHvVQ4BpPtbdYWYOeX5oGBUIvjhpmggHWn5fzDhUzluYAQAZd43zv5IgaHTAr089whplo1tXNMQgItGBlcXwxlR+C89mvSUuJqgTcs/si5QNArrNa98YkkYR+fyGM2+jdNGKFNfPoUb1jfSmdeyGsPiZ+UCaPyMfXcdp8Afo6vOUDjDvJSXkDlNmhrOcUrkJolm/gKMat6ibFnP/5kHukv15/gx03XzDXNjFKrK3vqj/DD+gWnCa9+B+JDKzCfjjEk8QIDAQAB"
```

**Description**: The manifest contains a hardcoded public key used for Chrome extension ID generation. This is standard practice for maintaining consistent extension IDs across updates.

**Verdict**: **False Positive**. This is a legitimate Chrome Web Store public key, not a secret API key.

### 6. External API Communications
**Severity**: LOW
**Files**: `background.bundle.js:39794`, `background.bundle.js:40220`
**Code**:
```javascript
// Fetches fee details from SellerApp API
"https://api.sellerapp.com/amazon/us/research/new/extension/free_tool/profit_calculator?geo=".concat(Co[t], "&product_id=").concat(e, "&listing_price=").concat(r, "&shipping_price=").concat(a)

// Fetches product details
"https://api.sellerapp.com/amazon/us/research/new/extension/free_tool/product_details?productIds=".concat(e, "&geo=").concat(Co[t], "&price_detail=1&ratings=true&fee_detail=true&product_specifications=true")
```

**Description**: The extension sends product ASINs and pricing data to SellerApp's API for FBA calculations.

**Verdict**: **Expected behavior**. The extension's core functionality requires sending product data to calculate Amazon fees. No sensitive user credentials are transmitted (API uses `x-client: plugin` header for identification).

## False Positives

| Pattern | Location | Reason |
|---------|----------|--------|
| Axios authentication headers | background.bundle.js:32-33 | Standard HTTP Basic Auth implementation in Axios library |
| `new Function()` for Regenerator | background.bundle.js:20351 | Babel regenerator-runtime polyfill initialization, benign |
| React error messages | contentScript.bundle.js:7157 | React development error handler, standard framework code |
| MUI/Emotion CSS-in-JS | contentScript.bundle.js:1-1000 | Emotion styling library framework code |
| `innerHTML` usage | contentScript.bundle.js:7640,11154 | React DOM manipulation, standard rendering |
| `dangerouslySetInnerHTML` | contentScript.bundle.js:4117 | React prop validation definition, not actual usage |
| `password` input types | contentScript.bundle.js:3524,5058,8659 | React form field type definitions, not capturing passwords |
| `keydown`/`keypress` listeners | contentScript.bundle.js:8306-8638 | React synthetic event system framework code |
| `addEventListener` patterns | contentScript.bundle.js:3566,5098 | Floating UI focus management for accessibility |
| `btoa` usage | background.bundle.js:33 | Standard HTTP Basic authentication encoding in Axios |
| `document.cookie` access | background.bundle.js:549,552,28952-28955 | Axios HTTP cookie handling for session management |
| Recent search deletion | background.bundle.js:20806 | Clears test "samsung" search used for login detection |

## API Endpoints

| Endpoint | Purpose | Data Sent | Risk Level |
|----------|---------|-----------|------------|
| `wss://scrapernet.sellerapp.com/scraper-net/websocket` | Scraping proxy coordination | User IP, geo, zip code, login status, scraped HTML, socket_id, instance_id | HIGH |
| `https://api.sellerapp.com/.../profit_calculator` | FBA fee calculation | ASIN, listing price, shipping price, geo | LOW |
| `https://api.sellerapp.com/.../product_details` | Product data enrichment | Product IDs, marketplace | LOW |
| `https://lumtest.com/myip.json` | IP geolocation | None (receives IP/country) | LOW |
| `https://{amazon}/portal-migration/hz/glow/address-change` | Amazon zip code manipulation | zip_code, anti-csrftoken-a2z | MEDIUM |
| `https://{amazon}/rufus/web/renderedAnswer` | Amazon Rufus AI scraping | query, ASIN, anti-csrftoken-a2z | MEDIUM |
| `https://completion.{amazon}/api/2017/recentsearches` | Clear test search history | Deletes "samsung" test search | LOW |
| `https://www.sellerapp.com/chrome-feedback.html` | Uninstall feedback | None (redirect only) | LOW |

## Data Flow Summary

1. **User browses Amazon product** → Content script extracts ASIN → Sends to background script
2. **Background script**:
   - Connects to SellerApp WebSocket with user IP/geo/zip/login status
   - Receives scraping jobs from SellerApp backend
   - Fetches Amazon URLs using user's session/IP
   - Parses HTML with custom schemas
   - Sends parsed data back to SellerApp
3. **Fee calculation**: Queries SellerApp API and Amazon's public fee API with product data
4. **Results display**: Content script injects UI overlay on Amazon pages

**Critical Issues**:
1. Users become unwitting nodes in SellerApp's commercial scraping infrastructure, potentially violating Amazon's ToS and exposing their accounts to risk
2. Extension can remotely modify user Amazon account settings (zip code) without per-action consent
3. Extensive telemetry including IP addresses, geolocation, and multi-marketplace login status transmitted to SellerApp

**Supported Scraping Page Types**:
- `KEYWORD_SEARCH` - Amazon search results (multi-page support)
- `PRODUCT_LISTING` - Product detail pages
- `SELLER_PROFILE` - Seller information pages
- `QNA_DETAILS` - Q&A sections
- `REVIEW_DETAILS` - Customer reviews
- `BEST_SELLER` - Best seller rankings
- `OFFERS_DETAILS` - Product offers
- `RUFUS_DETAILS` - Amazon Rufus AI responses (including anti-CSRF token theft for POST requests)

## Overall Risk Assessment

**MEDIUM**

### Breakdown:
- **CRITICAL findings**: 0
- **HIGH findings**: 0
- **MEDIUM findings**: 3 (Residential proxy infrastructure, Session harvesting, Account manipulation)
- **LOW findings**: 3 (External extension communication, Expected API communications, Public key in manifest)

### Rationale:
While the extension provides legitimate FBA calculation functionality, it operates a **hidden residential proxy network** using users' browsers to scrape Amazon at scale. This is not disclosed in the extension description and presents:
- Privacy risks (IP/location tracking)
- Account risks (potential Amazon ToS violations)
- Resource abuse (bandwidth consumption)

The extension is **not outright malicious** (no credential theft, no malware), but employs **deceptive practices** common in market intelligence tools that repurpose user traffic for commercial data harvesting.

### Recommendations:

**For SellerApp (Developer)**:
1. **Transparent Disclosure**: Clearly inform users in Chrome Web Store listing that:
   - Their browser participates in distributed web scraping
   - Their IP address will be used for commercial data collection
   - Their Amazon account settings may be temporarily modified
   - Bandwidth will be consumed for scraping operations
2. **Opt-in Consent**: Make scraping participation opt-in with explicit warnings about Amazon ToS risks
3. **Data Minimization**: Avoid transmitting user IP addresses to WebSocket server
4. **User Control**: Provide dashboard showing scraping activity and option to disable background scraping

**For Users**:
1. **Understand Risk**: Installing this extension means:
   - Amazon scraping activity originates from your IP address
   - SellerApp can temporarily change your Amazon delivery location
   - Your Amazon login status across 23 marketplaces is monitored
   - You may violate Amazon's Terms of Service regarding automated access
2. **Monitor Activity**: Watch for unexpected Amazon account location changes
3. **Consider Alternatives**: Use official Amazon seller tools if concerned about ToS compliance

**For Platform Reviewers**:
1. Consider whether residential proxy functionality should require explicit user consent
2. Evaluate if Chrome Web Store policies require disclosure of distributed scraping infrastructure
3. Review if automatic account manipulation (zip code changes) violates platform guidelines

## Technical Notes

**Positive Security Indicators**:
- ✅ Manifest V3 with minimal declared permissions (only `storage`)
- ✅ No credential interception or password keylogging detected
- ✅ No obfuscation beyond standard webpack bundling
- ✅ No remote code execution via eval() or Function() (only polyfill usage)
- ✅ No ad/coupon injection detected
- ✅ No cryptocurrency mining
- ✅ No extension enumeration/killing behavior
- ✅ Uses standard libraries: Axios (HTTP), React (UI), Emotion (CSS-in-JS), Material-UI
- ✅ No XHR/fetch hooking for credential theft

**Negative Security Indicators**:
- ⚠️ WebSocket-based remote command & control infrastructure
- ⚠️ Uses user browsers as residential proxy nodes
- ⚠️ Transmits user IP addresses and geolocation to third-party
- ⚠️ Can remotely modify Amazon account settings
- ⚠️ Monitors login status across 23 Amazon marketplaces
- ⚠️ Persistent tracking via socket_id stored in chrome.storage.local
- ⚠️ Accepts commands from external extension (cross-extension communication)

**Supported Amazon Marketplaces** (23 total):
US, CA, MX, BR, GB, DE, FR, IT, ES, NL, SE, PL, BE, IE, TR, EG, AE, SA, IN, JP, AU, SG, ZA

**WebSocket Reconnection Logic**:
- Initial retry delay: 1000ms
- Max retry delay: 60000ms (1 minute)
- Max retry attempts: 100
- Exponential backoff on failures
- Persistent connection maintained 24/7 when extension is active

**Health Check**:
- Sends ping every 30 seconds via WebSocket
- Includes zip code in health check payload
- Logs connection status to console
