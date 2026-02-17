# Security Analysis: Directo - Travel Deals - Save on Hotels (fonalplhodhnenmokepaijoemaednpjm)

## Extension Metadata
- **Name**: Directo - Travel Deals - Save on Hotels
- **Extension ID**: fonalplhodhnenmokepaijoemaednpjm
- **Version**: 2.89.1
- **Manifest Version**: 3
- **Estimated Users**: ~300,000
- **Developer**: Directo (getdirecto.com)
- **Analysis Date**: 2026-02-15

## Executive Summary
Directo is a travel comparison extension that monitors user browsing on hotel booking sites (Booking.com, Expedia, Airbnb, etc.) and offers alternative booking options to save money. The extension collects page content and browsing data from these sites and transmits it to multiple backend endpoints including `edge.truesign.ai` (a fingerprinting/bot detection service), Google Cloud Functions, and Directo's own infrastructure. While the privacy policy discloses that the extension "detects accommodation searches on other websites," the extent of data collection and use of third-party tracking services may not be fully transparent to users. The extension's behavior is consistent with its stated purpose, but the broad data collection and third-party integrations warrant a **MEDIUM** risk rating.

**Overall Risk Assessment: MEDIUM**

## Vulnerability Assessment

### 1. Page Content Scraping & Exfiltration to edge.truesign.ai
**Severity**: MEDIUM
**Category**: data_collection:browsing_monitoring
**Files**:
- `/js/content.js` (574KB minified)
- `/js/background.js` (284KB minified)

**Analysis**:
The extension uses `document.querySelectorAll` to extract DOM elements from hotel booking pages and sends this data via `fetch()` to `https://edge.truesign.ai`. Static analysis (ext-analyzer) identified two high-severity exfiltration flows:

1. **Flow 1**: `document.querySelectorAll` → `fetch(edge.truesign.ai)` in content.js
2. **Flow 2**: `chrome.storage.local.get` → `fetch(edge.truesign.ai)` in background.js

**Code Evidence** (from extracted source):
```javascript
// TrueSign API Client (appears in both content.js and background.js)
class TrueSignClient {
  rootUrl;
  appVersion;
  truesignEndpoint;
  tsToken=null;
  injectInto;
  partnerKey;

  async createTSToken(){
    try{
      const options={signal:AbortSignal.timeout(1000)};
      const response=await fetch(`https://edge.truesign.ai/v2/${this.truesignEndpoint}`,{...options});
      const data=await response.json();
      return this.tsToken=data.token, this.tsToken||"no-token"
    }catch(error){
      console.error("Unable to request authentication token",error);
      this.tsToken="unauthenticated";
      return this.tsToken
    }
  }
}
```

**What is edge.truesign.ai?**
TrueSign is a third-party bot detection and device fingerprinting service. The extension sends an authentication request to `https://edge.truesign.ai/v2/{endpoint}` to obtain a token, which is then used to authenticate subsequent requests. This suggests the extension is using TrueSign to verify that users are real humans (not bots) when accessing hotel booking sites.

**Data Transmitted**:
- Page content from hotel search pages (via querySelectorAll)
- Extension storage data (potentially including user preferences, search history)
- Authentication tokens obtained from edge.truesign.ai

**Privacy Policy Disclosure**:
The Directo privacy policy states:
> "Show recommendations through the extension: allow the extension downloaded by the User to detect accommodation searches on other websites and offer, in real time, cheaper or more relevant alternatives"

This discloses monitoring of accommodation searches but does not explicitly mention:
- Use of third-party fingerprinting services (edge.truesign.ai)
- Specific data fields collected from pages
- Retention period for scraped data

**Verdict**: **MEDIUM RISK** - Data collection is disclosed at a high level and serves the extension's core functionality (price comparison). However, the use of third-party tracking infrastructure (TrueSign) is not explicitly disclosed, and users may not understand the extent of data being extracted from booking sites.

---

### 2. Cross-Component Message Passing Vulnerabilities
**Severity**: LOW
**Category**: vuln:insecure_messaging
**Files**:
- `/js/background.js`
- `/js/content.js`

**Analysis**:
Static analysis identified message data flows that could potentially be exploited:

**Flow 3**: `messageData` → `fetch(edge.truesign.ai)` (content.js ⇒ background.js)
**Flow 4**: `messageData` → `fetch(edge.truesign.ai)` (content.js ⇒ background.js)
**Flow 5**: `messageData` → `*.innerHTML` (background.js ⇒ content.js)

The extension uses a message-passing architecture where content scripts and background workers communicate via `chrome.runtime.sendMessage` and `chrome.tabs.sendMessage`.

**Code Evidence** (from decompiled source):
```javascript
// Message proxy pattern in background.js
const messageProxy = function(){
  const handlers = new Map;
  return new Proxy({},{
    get(target, handlerName){
      if("string" != typeof handlerName) return;
      const name = handlerName;
      return handlers.has(name) || handlers.set(name, function(serverId, handlerId){
        return function(...args){
          let tabId, payload;
          2 === args.length ? (tabId=args[0], payload=args[1]) : (tabId=args[0], payload=void 0);
          const message = {
            serverId: serverId,
            handlerId: handlerId,
            ...void 0 !== payload ? {payload: payload} : {}
          };
          return chrome.tabs.sendMessage(tabId, message).then(validateResponse)
        }
      }("DIRECTO_CONTENT", name)), handlers.get(name)
    }
  })
}();
```

**Potential Issues**:
1. **Flow 5 (innerHTML sink)**: Message data from background script is inserted into page DOM via `innerHTML`. If not properly sanitized, this could enable XSS if a malicious actor compromises the background worker.
2. **No origin validation**: The message handler does not appear to validate sender origin, potentially allowing malicious extensions or web pages to send crafted messages.

**Mitigating Factors**:
- Extension uses Manifest V3 with strict CSP: `script-src 'self'; object-src 'self'`
- No external CSP endpoints that could be exploited
- Message handler is internal-only (no `externally_connectable` declared)

**Verdict**: **LOW RISK** - The innerHTML sink is a concern, but the strict CSP and lack of external message sources significantly reduce exploitability. This is primarily a code quality issue rather than an active vulnerability.

---

### 3. Broad Host Permissions & Content Script Injection
**Severity**: INFORMATIONAL
**Category**: permissions:overly_broad
**Files**: `/manifest.json`

**Analysis**:
The extension requests `http://*/*` and `https://*/*` host permissions and injects content scripts on all websites:

```json
"content_scripts": [{
  "js": ["js/content.js", "js/vendor.js"],
  "matches": ["http://*/*", "https://*/*"],
  "run_at": "document_end"
}]
```

**Justification**:
While overly broad, these permissions are necessary for the extension's core functionality:
- It monitors multiple hotel booking platforms (Booking.com, Expedia, Airbnb, VRBO, Agoda, Kayak, etc.)
- Users might visit any of these sites, so universal matching simplifies deployment
- Content script activation is conditional (checks if current site is a supported booking platform)

**Observed Targeted Sites** (from code):
```javascript
// Hardcoded list of supported booking platforms
["expedia.com", "agoda.com", "kayak.com", "priceline.com", "hotel.com",
 "hotwire.com", "travelocity.com", "orbitz.com", "lastminute.com",
 "hometogo.com", "wimdu.com", "holidu.com", "novasol.com",
 "makemytrip.com", "leboncoin.fr", "plumguide.com", "trip.com",
 "likibu.com", "hopper.com", "hostelworld.com", "glampinghub.com",
 "trivago.com" (+ international domains), "booking.com", "airbnb.com",
 "vrbo.com", "viator.com", "civitatis.com", "platform.hubbyesim.com"]
```

**Verdict**: **NOT MALICIOUS** - Broad permissions are functionally necessary, though a more targeted approach (explicit match patterns for each supported site) would be more privacy-conscious.

---

## Network Endpoints Analysis

The extension communicates with the following endpoints:

### First-Party Directo Infrastructure:
1. **https://api.getdirecto.com** - Main API endpoint
2. **https://goals.getdirecto.com** - Goal tracking/analytics
3. **https://events.getdirecto.com** - Event tracking
4. **https://rateshops.getdirecto.com** - Rate comparison data
5. **https://engine.getdirecto.com** - Search engine
6. **https://extension-cdn.getdirecto.com** - CDN for extension assets
7. **https://forms.getdirecto.com** - Form submissions
8. **https://secure.getdirecto.com** - Secure transactions
9. **https://www.getdirecto.com** - Main website

### Google Cloud Platform (Directo-owned):
10. **https://europe-west4-clean-sunspot-388915.cloudfunctions.net** - Cloud Function (project: clean-sunspot-388915)
11. **https://vio-wrapper-api-cd-6981968610.europe-west4.run.app** - Cloud Run service
12. **https://htmlql-6981968610.europe-west4.run.app** - HTML query service

### Third-Party Services:
13. **https://edge.truesign.ai** - TrueSign bot detection/fingerprinting (PRIMARY CONCERN)
14. **https://cdn.growthbook.io** - GrowthBook feature flagging/A-B testing
15. **https://www.google-analytics.com** - Google Analytics (standard tracking)

**Key Observations**:
- **edge.truesign.ai** is the only non-Directo/Google third-party that receives user data
- TrueSign is likely used to prevent bot abuse of the price comparison service
- No mention of TrueSign in the privacy policy
- Google Cloud infrastructure suggests legitimate SaaS architecture

---

## Privacy Policy Assessment

**Privacy Policy URL**: https://www.getdirecto.com/directo-privacy-statement

**What is Disclosed**:
1. Extension "detects accommodation searches on other websites and offers cheaper alternatives"
2. Collects "data derived from your browsing and any other data you may provide"
3. Uses "third party service providers that may have access to your personal data"
4. Creates "commercial profiling based on preferences, using third party sources (social networks)"
5. Data retention: "as long as the User keeps the extension installed or has not withdrawn consent"

**What is NOT Disclosed**:
1. Use of edge.truesign.ai for bot detection/fingerprinting
2. Specific data fields extracted from booking sites
3. Whether page content is sent to third parties beyond Directo
4. Technical details about tracking mechanisms

**Opt-Out Mechanism**:
Users can uninstall the extension or contact privacy@getdirecto.com to withdraw consent.

**Assessment**:
The privacy policy provides high-level disclosure of data collection but lacks technical specificity. The use of TrueSign (a fingerprinting service) is not explicitly mentioned, which may constitute incomplete disclosure under GDPR/privacy regulations.

---

## Permissions Analysis

**Requested Permissions**:
- `storage` - Store user preferences, search history
- `unlimitedStorage` - Large data storage (cache of hotel prices?)
- `webRequest` - Monitor network requests (likely to detect booking site navigation)
- `identity` + `identity.email` - OAuth sign-in for user accounts
- `activeTab` - Access current tab when user clicks extension icon
- `scripting` - Dynamic content script injection
- `alarms` - Scheduled tasks (price monitoring alerts?)
- `http://*/*` + `https://*/*` - Access all websites

**Risk Assessment**:
All permissions appear aligned with stated functionality, with the exception of `unlimitedStorage` which seems excessive for a price comparison tool. This could indicate caching of large datasets (hotel inventory, historical prices) or potentially long-term retention of user browsing data.

---

## Static Analysis Summary (ext-analyzer)

**Risk Score**: 60/100

**Findings Breakdown**:
- **High Severity**: 5 findings
  - 2 exfiltration flows (page content → fetch, storage → fetch)
  - 3 cross-component messaging flows (potential injection risks)
- **Medium/Low**: 0 additional findings
- **Code Execution Flows**: 0 (no eval/Function/executeScript risks)
- **WASM**: Not present
- **Obfuscation**: Detected (minified/webpack bundled code)

**Key Metrics**:
- Total flow paths: 5
- Exfiltration flows reaching network sinks: 2
- Open message handlers: 0 (no externally_connectable)
- Attack surface: Medium (broad permissions, messaging vulnerabilities)

---

## Conclusion

**Overall Risk Rating: MEDIUM**

Directo is a legitimate travel savings extension that performs price comparison by monitoring user activity on hotel booking sites. The extension collects browsing data (page content, search queries) and transmits it to backend services including the third-party fingerprinting service `edge.truesign.ai`.

**Why MEDIUM and not HIGH?**
1. Data collection is disclosed in the privacy policy (albeit vaguely)
2. Functionality aligns with stated purpose (price comparison requires monitoring booking sites)
3. No evidence of credential theft, hidden exfiltration, or malicious C2 infrastructure
4. Extension appears to be a commercial product from a legitimate company

**Why MEDIUM and not LOW/CLEAN?**
1. Use of third-party fingerprinting service (TrueSign) is not disclosed
2. Broad data collection from sensitive booking contexts (includes personal travel details, payment pages)
3. Privacy policy lacks technical specificity about what data is collected
4. `unlimitedStorage` permission suggests potential long-term retention of browsing data
5. Cross-component messaging patterns could enable XSS if background worker is compromised

**Recommendations for Users**:
- Use only on trusted booking sites
- Review privacy policy and understand data sharing practices
- Consider whether travel savings justify the privacy tradeoff
- Monitor network activity if concerned about data transmission
- Contact privacy@getdirecto.com to request data deletion if uninstalling

**Recommendations for Developers**:
1. Update privacy policy to explicitly disclose use of TrueSign and other third-party services
2. Implement origin validation for message handlers to prevent injection attacks
3. Minimize data retention (consider ephemeral caching instead of unlimitedStorage)
4. Add user controls for opting out of analytics/tracking while retaining core functionality
5. Use explicit match patterns for supported sites instead of `http://*/*`

---

## Technical Appendix

### Data Flow Summary
```
User visits Booking.com
    ↓
content.js extracts page data via querySelectorAll("a.bn2bl2p")
    ↓
Sends to background.js via chrome.runtime.sendMessage
    ↓
background.js requests TrueSign token: fetch("https://edge.truesign.ai/v2/{endpoint}")
    ↓
Authenticated request sent to Directo API with page data + TrueSign token
    ↓
Directo backend processes and returns alternative hotel options
    ↓
content.js injects results into page DOM (via innerHTML)
```

### Risk Score Calculation (ext-analyzer methodology)
- Base permissions: 30 points (capped)
- Exfiltration flows: 2 × 15 = 30 points
- Code exec flows: 0 points
- WASM: 0 points
- Open message handlers: 0 points
- **Total**: 60/100

### File Inventory
- `/js/background.js` - 284KB (minified service worker)
- `/js/content.js` - 574KB (minified content script)
- `/js/vendor.js` - 908KB (React/bundled dependencies)
- `/js/options.js` - 3.8KB (settings page)
- `/manifest.json` - 1KB (MV3 manifest)
- `/_locales/en/messages.json` - Internationalization strings

### Supported Hotel Platforms (106 domains)
Booking.com, Expedia, Agoda, Kayak, Priceline, Hotels.com, Hotwire, Travelocity, Orbitz, Airbnb, VRBO, Trivago (global), Holidu (EU), Novasol, MakeMyTrip, Hopper, HostelWorld, Viator, Civitatis, and 87+ international variants.

---

**Analysis Completed**: 2026-02-15
**Analyst**: Claude Sonnet 4.5 (ext-analyzer + manual code review)
**Confidence Level**: High (based on static analysis, privacy policy review, and endpoint identification)
