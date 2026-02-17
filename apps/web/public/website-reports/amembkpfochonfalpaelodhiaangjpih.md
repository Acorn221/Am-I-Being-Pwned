# Vulnerability Report: AliAssist: shopping assistant

## Metadata
- **Extension ID**: amembkpfochonfalpaelodhiaangjpih
- **Extension Name**: AliAssist: shopping assistant
- **Version**: 0.0.0.76
- **Users**: ~100,000
- **Manifest Version**: 3
- **Analysis Date**: 2026-02-14

## Executive Summary

AliAssist is a shopping assistant extension that advertises itself as a tool to "search by image on the biggest Chinese marketplace to find the best prices." While the extension does provide legitimate shopping assistance features (product comparison, reviews analysis, price calculators), it engages in aggressive and largely undisclosed affiliate link injection across 40+ platforms including e-commerce sites, gambling platforms, and forex trading sites.

The extension automatically redirects users visiting specific URLs to affiliate versions of those pages, often without clear disclosure. Most concerning is its inclusion of gambling/betting platforms (1xbet, Blaze, Brazino, Stake, etc.) and high-risk forex/binary options platforms (Binomo, IQ Option, Olymp Trade) in its affiliate program—functionality completely unrelated to the extension's stated shopping assistant purpose. Additionally, the extension contains an unvalidated postMessage listener that could enable DOM-based XSS attacks.

**Risk Classification: HIGH** — Due to undisclosed affiliate injection for gambling platforms, lack of transparency, potential privacy violations through browsing tracking, and a DOM-based XSS vulnerability.

## Vulnerability Details

### 1. HIGH: Undisclosed Affiliate Link Injection for Gambling/Betting Platforms
**Severity**: HIGH
**Files**: globalProgram.bundle.js (lines 247-375), navigationListener.bundle.js, navigationHelper.bundle.js
**CWE**: CWE-506 (Embedded Malicious Code)

**Description**: The extension automatically injects affiliate links for gambling, betting, and high-risk trading platforms—functionality completely unrelated to its advertised purpose as a shopping assistant for AliExpress/Amazon.

**Evidence**:
```javascript
// globalProgram.bundle.js - Lines 247-262
{
  plataformName: "1xbet",
  redirects: [{
    hrefRegex: /^https:\/\/([a-z]{2,}\.)?1xbet\.com\/[a-z]{2}\/registration.*/,
    affiliateUrl: "https://www.afiliapub.com/affiliates/scripts/click.php?a_aid=35458573&a_bid=fb9a1a54",
    hourlyTimeframe: 0
  }, {
    hrefRegex: /^https:\/\/([a-z]{2,}\.)?1xbet\.com\/[a-z]{2}/,
    affiliateUrl: "https://www.afiliapub.com/affiliates/scripts/click.php?a_aid=35458573&a_bid=fb9a1a54",
    hourlyTimeframe: 1,
    redirectsToDeadlockPage: !0
  }]
},
{
  plataformName: "blaze",
  redirects: [{
    hrefRegex: /^https:\/\/blaze\.com/,
    affiliateUrl: "https://blaze.cxclick.com/visit/?bta=47606&brand=blaze",
    hourlyTimeframe: 1,
    redirectsToDeadlockPage: !0
  }]
},
{
  plataformName: "brazino",
  redirects: [{
    redirectName: "register",
    hrefRegex: /^https:\/\/www\.brazino777\.bet\.br\/auth\/register([?&].*)?/,
    affiliateUrl: "https://brazpromo.com/promo/click/6823b82d007a5",
    hourlyTimeframe: 0
  }]
},
{
  plataformName: "stake",
  redirects: [{
    hrefRegex: /^https:\/\/stake\.com\/[a-z]{2}$/,
    affiliateUrl: "https://stake.com/?c=j4DMpcnQ",
    hourlyTimeframe: 0,
    redirectsToDeadlockPage: !0
  }]
}
```

The extension monitors ALL page navigations and silently redirects users to affiliate versions when visiting these gambling platforms.

**Analysis**:
- The extension description mentions nothing about gambling, betting, or trading platforms
- Users installing a "shopping assistant" for AliExpress have no reason to expect gambling affiliate injection
- `hourlyTimeframe: 0` means immediate redirect on every visit (no throttling)
- `redirectsToDeadlockPage: !0` flag suggests some URLs intentionally trap users

**Verdict**: **HIGH SEVERITY** — This is deceptive behavior. Users installing a shopping assistant should not have their gambling/betting site visits monetized without explicit consent. This violates user trust and Chrome Web Store policies regarding undisclosed affiliate programs.

---

### 2. HIGH: Unvalidated postMessage Listener (DOM-based XSS Risk)
**Severity**: HIGH
**Files**: runTour.bundle.js (line 3)
**CWE**: CWE-940 (Improper Verification of Source of a Communication Channel)

**Description**: The extension contains a global postMessage listener without origin validation that directly uses message data to construct DOM content.

**Evidence**:
```javascript
// runTour.bundle.js - Lines 3-36
window.addEventListener("message", (t => {
  t.source === window && "ali-assist-extension" === t.data?.source &&
  "function" == typeof window.introJs && "SET_I18N" === t.data.type &&
  (e = t.data.payload, introJs.tour().setOptions({
    steps: [{
      element: document.querySelector("#ali-helper-bottom-bar-button-wrapper-reviews"),
      intro: e.reviewsStep  // UNSANITIZED USER INPUT
    }, {
      element: document.querySelector("#ali-helper-bottom-bar-button-wrapper-super-search"),
      intro: e.superSearchStep  // UNSANITIZED USER INPUT
    },
    // ... more steps using e.step2, e.step3, e.step4, e.step5, e.step6
    {
      element: document.querySelector('[class^="main-image--wrap--"]'),
      intro: `
        <p>${e.step6}</p>
        <img src="https://primaz-aliexpress-bot.herokuapp.com/images/search-by-image-intro.gif" style="padding-top:20px; "/>
      `  // DIRECT HTML INJECTION FROM MESSAGE DATA
    }],
    // ...
  }).start())
}))
```

**Analysis**:
- The listener only checks `t.source === window` (self-origin) and `t.data?.source === "ali-assist-extension"`
- No cryptographic validation or nonce verification
- Any page script can post a message with `source: "ali-assist-extension"` and inject arbitrary HTML into the `intro` fields
- IntroJS renders these `intro` strings as HTML, enabling XSS
- Attack vector: Malicious website scripts or other extensions can post crafted messages to inject malicious HTML/JS into the guided tour

**Verdict**: **HIGH SEVERITY** — While exploitation requires the victim to be on a page where an attacker controls script execution, the impact is full XSS within the extension's context. Modern postMessage handlers should validate origin and sanitize all user-controlled data.

---

### 3. MEDIUM: Undisclosed Browsing Activity Tracking and Monetization
**Severity**: MEDIUM
**Files**: navigationListener.bundle.js, navigationHelper.bundle.js, shopeeIndex.bundle.js, searchHelper.bundle.js, alibabaIndex.bundle.js, temuIndex.bundle.js
**CWE**: CWE-359 (Exposure of Private Information)

**Description**: The extension tracks user browsing patterns across e-commerce platforms to implement sophisticated affiliate link injection with visit counters and cooldown timers.

**Evidence**:
```javascript
// navigationHelper.bundle.js - Lines 92-119
function checkForRedirection() {
  const visitCounter = localStorage.getItem(`${prefix}-counter`) ?
    parseInt(localStorage.getItem(`${prefix}-counter`)) : 0;

  if (visitCounter === 0 || visitCounter > 3) {
    // Redirect to affiliate link
    chrome.runtime.sendMessage({
      type: "getShopeeAffiliateLink",
      data: { productUrl: window.location.href.split("?")[0] }
    }, (response => {
      if (response.result !== "") {
        setCounter(1);
        location.assign(response.result);  // AUTOMATIC REDIRECT
      }
    }));
  } else {
    const next = visitCounter + 1;
    setCounter(next);
  }
}

// searchHelper.bundle.js - Line 72
location.assign(`https://apyecom.com/click/672bcf2b2bfa816dec0427f3/349046/subaccount/url=${currentUrl()}`)

// shopeeIndex.bundle.js - Line 96
location.assign(affiliateResponse.result)
```

**Analysis**:
- Extension tracks which products users visit and how frequently
- Implements "every 4th visit" redirect logic on Shopee
- Stores timestamps and visit counters in localStorage
- Sends product URLs to backend API at `primaz-aliexpress-bot.herokuapp.com`
- No privacy policy disclosure visible in extension metadata

**Platforms monitored for affiliate injection**:
- **E-commerce**: Shopee, AliExpress, Alibaba, Amazon, Mercado Livre, Temu, Shein, Kabum, Carrefour, Madeira Madeira, Netshoes, Centauro, Vivara, Acer, Adidas, Riachuelo, etc.
- **Gambling/Betting**: 1xbet, Blaze, Brazino, Estrela Bet, Stake, Superbet
- **Forex/Trading**: Binomo, Olymp Trade, IQ Broker, Ebinex
- **Airlines**: Gol
- **Cashback**: Meliuz
- **Online Learning**: Udemy

**Verdict**: **MEDIUM SEVERITY** — While affiliate programs are legitimate business models, users should be explicitly informed. The extension description mentions finding "best prices" but doesn't disclose that URLs will be rewritten to include affiliate codes, nor that browsing behavior is tracked.

---

### 4. MEDIUM: Remote Code Execution Risk via Heroku Backend
**Severity**: MEDIUM
**Files**: background.bundle.js (line 233), all content scripts
**CWE**: CWE-494 (Download of Code Without Integrity Check)

**Description**: The extension relies heavily on a remote backend (`primaz-aliexpress-bot.herokuapp.com`) for critical functionality without apparent integrity checks.

**Evidence**:
```javascript
// background.bundle.js - Line 233
static _backendUrl = "https://primaz-aliexpress-bot.herokuapp.com"

// API endpoints called:
- /smart-match?productId=...
- /super-search?productId=...
- /product-details?q=...
- /ali-help-with-client?q=...&client=...
- /shopee-help?q=...
- /amazon-help?q=...&countryCode=...
- /v2/search-for-product
- /upload-image
- /product-reviews?productId=...
- /ali-hot-products
```

**Analysis**:
- All responses from the backend are treated as trusted
- No signature verification or response validation visible
- If the Heroku backend is compromised, attackers could:
  - Inject malicious JavaScript into product listings
  - Redirect users to phishing sites instead of legitimate products
  - Exfiltrate user search queries and browsing patterns
- Heroku free tier apps can be sleeping and wake on request, creating availability concerns
- Backend also serves image URLs directly embedded into the extension UI

**Verdict**: **MEDIUM SEVERITY** — While the code doesn't execute arbitrary backend responses as code, the backend controls critical data flows including URLs users are redirected to and content injected into pages. A compromised backend could facilitate phishing or data exfiltration.

---

### 5. LOW: Excessive Permissions for Stated Functionality
**Severity**: LOW
**Files**: manifest.json
**CWE**: CWE-250 (Execution with Unnecessary Privileges)

**Description**: Content scripts run on `<all_urls>` at `document_end`, giving the extension broad access to all websites user visits.

**Evidence**:
```json
// manifest.json - Lines 8-25
"content_scripts": [
  {
    "matches": ["<all_urls>"],
    "js": [
      "index.bundle.js",
      "searchByImage.bundle.js",
      "navigationListener.bundle.js",
      "navigationHelper.bundle.js",
      "globalProgram.bundle.js",
      "imageSearchContent.bundle.js",
      "searchHelper.bundle.js",
      "imageConverter.bundle.js",
      "translationsHandler.bundle.js",
      "superSearch.bundle.js",
      "productReviews.bundle.js"
    ],
    "run_at": "document_end"
  }
]
```

**Analysis**:
- 11 content script bundles injected into every page user visits
- `globalProgram.bundle.js` alone is 109KB with 40+ platform redirect rules
- This creates significant performance overhead and privacy exposure
- Most of the code is only relevant on specific e-commerce platforms
- Could be refactored to use more specific matches for each platform

**Verdict**: **LOW SEVERITY** — While excessive, this is technically necessary for the affiliate injection to work across all target platforms. However, it represents poor engineering practice and creates unnecessary attack surface.

---

## False Positives Analysis

| Pattern | Why It's Legitimate | Notes |
|---------|-------------------|-------|
| Storage API calls → fetch() | Extension stores user preferences (language, currency) and sends them to backend for localized product search | Expected for shopping assistant functionality |
| chrome.tabs.query → fetch() | Background script relays product search requests from content scripts | Normal message passing pattern |
| Product data → fetch(flagcdn.com, icons8.com) | Fetching country flags and UI icons for product reviews | Third-party CDN usage is common |
| DOM queries → fetch() | Reading product IDs from page to search for alternatives | Core functionality |
| Multiple affiliate domains | Shopping assistant needs to work across many e-commerce platforms | However, gambling/trading sites are NOT legitimate |

---

## API Endpoints Analysis

| Endpoint | Purpose | Data Transmitted | Risk Level |
|----------|---------|------------------|------------|
| primaz-aliexpress-bot.herokuapp.com | Primary backend for product search, affiliate link generation | Product URLs, user preferences (language, currency), search images | **HIGH** - Central point of failure and data collection |
| apyecom.com | Affiliate network for Alibaba redirects | Full product URLs | **MEDIUM** - Third-party tracker |
| www.awin1.com | Awin affiliate network (legitimate retailers: Kabum, Carrefour, Vivara, etc.) | Click tracking | **LOW** - Standard affiliate platform |
| flagcdn.com | Country flag images for product reviews | None (CDN) | **LOW** - Static assets |
| img.icons8.com | UI icons | None (CDN) | **LOW** - Static assets |
| blaze.cxclick.com | Gambling affiliate network | Click tracking | **HIGH** - Undisclosed gambling promotion |
| brazpromo.com | Gambling affiliate network | Click tracking | **HIGH** - Undisclosed gambling promotion |
| afiliapub.com | Multi-platform affiliate network (includes 1xbet, Superbet) | Click tracking | **HIGH** - Undisclosed gambling promotion |
| apretailer.com.br | Brazilian affiliate network | Click tracking | **MEDIUM** - Some legitimate, some gambling |
| onelink.shein.com | Shein deep linking | Click tracking | **LOW** - Expected for fashion e-commerce |

---

## Data Flow Summary

1. **User visits product page** → Content scripts detect URL pattern
2. **Visit counter checked** → localStorage tracks visit frequency per platform
3. **Cooldown evaluated** → Hourly/daily rate limits prevent excessive redirects
4. **Backend API called** → Product URL sent to primaz-aliexpress-bot.herokuapp.com
5. **Affiliate link returned** → Backend generates affiliate URL via partner networks
6. **Automatic redirect** → `location.assign()` navigates user to affiliate version
7. **User session tracked** → Affiliate networks place cookies, extension increments counters

**Key privacy concerns**:
- Extension knows every product page user visits across 40+ platforms
- Product URLs transmitted to third-party backend (Heroku)
- Visit patterns stored in localStorage
- No apparent anonymization or data retention limits disclosed

---

## Manifest Analysis

**Permissions**:
- `contextMenus` - Used for right-click "search by image" feature ✓ Legitimate
- `storage` - Stores user preferences, visit counters, redirect timestamps ✓ Legitimate (but used for tracking)

**Content Scripts**:
- Injected on `<all_urls>` at `document_end`
- 11 separate bundle files totaling ~1.5MB deobfuscated
- Excessive but necessary for current architecture

**Host Permissions**:
- None explicitly declared
- Uses `<all_urls>` content script injection instead
- MV3 pattern, but gives equivalent broad access

**Web Accessible Resources**:
- `runTour.bundle.js` - Contains the postMessage vulnerability
- Bootstrap, IntroJS libraries - Standard UI frameworks
- Images - Static assets

---

## Overall Risk Assessment

**RISK LEVEL: HIGH**

**Justification**:

1. **Deceptive Functionality** — The extension advertises itself as a "shopping assistant" for finding prices on Chinese marketplaces (AliExpress), but secretly monetizes user visits to gambling, betting, and forex trading platforms with no disclosure. This is a clear violation of user trust and Chrome Web Store policies.

2. **DOM-based XSS Vulnerability** — The unvalidated postMessage listener in `runTour.bundle.js` allows arbitrary HTML injection into the IntroJS guided tour feature. While this requires the user to be on a page where an attacker controls script execution, it's a real security vulnerability that should be patched.

3. **Privacy Violations** — The extension tracks all product pages users visit across 40+ platforms, sends URLs to a third-party backend, and implements sophisticated visit counting/fingerprinting without disclosing this in the privacy policy or description.

4. **Undisclosed Affiliate Programs** — While affiliate link injection for shopping sites (Amazon, Shopee, etc.) could be considered legitimate if disclosed, the inclusion of gambling sites (1xbet, Blaze, Stake, Brazino) and high-risk trading platforms (Binomo, Olymp Trade) is wholly inappropriate for a "shopping assistant" and suggests the developer is prioritizing monetization over user benefit.

5. **Remote Backend Risk** — Heavy reliance on `primaz-aliexpress-bot.herokuapp.com` without apparent integrity checking means a backend compromise could redirect users to phishing sites or inject malicious content.

**Recommendations for Users**:
- **Remove this extension immediately** if you value privacy or were unaware of the gambling/betting affiliate injection
- Users who knowingly accept affiliate link injection for shopping might tolerate this, but should be aware their browsing data is being transmitted to third parties
- The postMessage vulnerability could be exploited by malicious websites

**Recommendations for Developer** (if acting in good faith):
1. Add explicit disclosure about affiliate link injection in the extension description and first-run experience
2. Remove gambling/betting/trading platforms from the affiliate program entirely (inappropriate for shopping assistant)
3. Fix the postMessage listener to validate origin and sanitize all message data
4. Implement integrity checking for backend responses
5. Add a privacy policy and reduce data collection/transmission
6. Refactor content scripts to only inject on relevant domains instead of `<all_urls>`

**Comparison to Similar Extensions**:
Many legitimate shopping assistants (Honey, Rakuten, Capital One Shopping) also inject affiliate links, but they:
- Explicitly disclose this in their descriptions and first-run flows
- Focus exclusively on shopping platforms (no gambling/betting)
- Are operated by established companies with public privacy policies
- Offer clear value proposition (price comparison, coupon finding)

AliAssist falls short on all these points, making it more similar to adware/malware than legitimate shopping assistants.
