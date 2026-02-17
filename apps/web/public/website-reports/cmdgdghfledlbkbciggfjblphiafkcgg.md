# Security Analysis: SBlock - Super Ad Blocker

**Extension ID:** cmdgdghfledlbkbciggfjblphiafkcgg
**Version:** 1.7.15
**Users:** ~900,000
**Risk Level:** MEDIUM
**Publisher:** Jimbo

## Executive Summary

SBlock presents itself as a legitimate ad blocker and does provide real ad-blocking functionality through Chrome's declarativeNetRequest API. However, the extension operates a sophisticated advertising intelligence operation that is not disclosed to users. It deploys specialized content scripts on Facebook, YouTube, Reddit, Twitter/X, Pinterest, TikTok, and Twitch that scrape detailed advertising metadata and transmit it to `addon.sblock.pro` for what appears to be advertising research or competitive intelligence gathering.

**Key Finding:** This is NOT a fake ad blocker like the smartadblocker.com network. SBlock provides legitimate ad-blocking functionality. However, it engages in undisclosed data collection that raises significant privacy concerns.

## Ad Blocking Functionality (Legitimate)

SBlock implements ad blocking through:

1. **declarativeNetRequest rules** - Multiple rulesets for blocking ads:
   - `default.json` - Primary ad blocking rules
   - `regions_0.json`, `regions_1.json`, `regions_2.json` - Regional rules
   - `social.json` - Social media tracking
   - `trackers.json` - Analytics/tracker blocking
   - `idcac.json` - Cookie consent popup blocking

2. **Content script injection** - CSS and scriptlet-based blocking similar to uBlock Origin
3. **Element picker** - Manual element blocking tool for users
4. **Web accessible resources** - Stub files to replace blocked scripts (google-analytics.js, etc.)

## Privacy Concerns: Advertising Intelligence Collection

### 1. Facebook Ad Scraping (MEDIUM Risk)

**File:** `special/scripts/facebook.js` (1900+ lines)

The extension injects a sophisticated scraper on facebook.com that:

- **Intercepts Facebook's internal GraphQL API** to extract ad metadata
- **Collects complete ad details:**
  - Ad ID, post ID, advertiser page information
  - Ad creative content (images, videos, text)
  - **Targeting data** (age ranges, interests, locations, demographics)
  - Advertiser fanpage data (followers, categories, contact info)
  - Call-to-action buttons and landing page URLs
- **Accesses Facebook's "Why Am I Seeing This?" (WAIST) data** containing:
  - User interests that triggered the ad
  - Demographics the advertiser targeted
  - Custom audiences used

**Data transmitted to:** `https://addon.sblock.pro/api/v1/external/data`

**Code evidence:**
```javascript
sendAd({
  ad,
  page: pageData,  // Advertiser fanpage info
  waist: waistData, // Targeting/interest data
});
```

The extension captures relationship status, education level, job titles, and other demographics that Facebook advertisers can target.

### 2. YouTube Ad Intelligence (MEDIUM Risk)

**File:** `special/scripts/youtube.js`

Scrapes YouTube ad data:
- Video ad IDs from intercepted requests
- Ad video metadata
- Placement information

**Code evidence:**
```javascript
window.postMessage({
  sender: 'sblock',
  eventName: config.EVENTS.AD_GET_DONE,
  params: { messageData: { data: ad, platform: 'youtube' } }
});
```

### 3. Other Platform Scraping

Similar data collection on:
- **Reddit** (`reddit.js`) - Promoted posts
- **Twitter/X** (`x.js`) - Promoted tweets
- **Pinterest** (`pinterest.js`) - Promoted pins
- **TikTok** (`tiktok.js`) - Sponsored content
- **Twitch** (`twitch.js`) - Video ads

### 4. Data Queue & Transmission

**File:** `background.js` - Variable `V` (adsQueue)

```javascript
var V = ({config:n, httpClient:t}) => {
  async function o(S) {
    let a = {...S, agent: q(c, i++)};
    delete a.retryCount;
    let {status:f, data:p} = await t.post(n.URLS.DATA_COLLECT, {body:a});
  }
  // Queue with retry logic
  return {
    async enqueue(S) {
      r.push({...S, retryCount:1});
      s || await l();
    }
  }
}
```

**Endpoint:** `https://addon.sblock.pro/api/v1/external/data`

The queue retries failed transmissions up to 5 times, ensuring data delivery.

## Security Vulnerabilities

### 1. PostMessage Without Origin Validation (LOW Risk)

**File:** `scripts/broker.js`

```javascript
window.addEventListener('message', (message) => {
  if (!runtime?.id || message.data?.sender !== 'sblock' || !message.data?.eventName) return;
  runtime.sendMessage({
    eventName: message.data.eventName,
    params: message.data.params,
  });
});
```

The broker only checks `message.data?.sender === 'sblock'` which any webpage can spoof. While the impact is limited since the extension validates event names, malicious pages could potentially trigger error conditions or noise in analytics.

**ext-analyzer finding:** `[HIGH] window.addEventListener("message") without origin check`

### 2. Third-Party Analytics Tracking

The extension sends telemetry to:
- **Google Analytics** (`G-MJSF1GSELS`) - User activation events
- **Datadog** - Error logging and metrics
- **ip-api.com** - User country detection

```javascript
GOOGLE_API: "https://www.google-analytics.com/mp/collect",
METRICS_API: "https://api.datadoghq.com/api/v2/series",
IP_TO_LOCATION: "http://ip-api.com/json/"
```

Hardcoded API keys exposed in code:
- `GOOGLE_API_SECRET: "Q4z3I3yiSzqjyMXV0BqQtA"`
- `LOGGER_TOKEN: "pubf8bd7d7be26b2468c87ab37bfa639fd8"`
- `METRICS_TOKEN: "3fd31b69678a1c5fa382332ba14b9868"`

## Business Model Analysis

SBlock appears to operate an **advertising intelligence service** where:

1. Users install the extension for ad blocking (which it provides)
2. Extension scrapes detailed ad data across major platforms
3. Data is aggregated at `addon.sblock.pro`
4. Likely monetized through:
   - Competitive intelligence for advertisers
   - Ad targeting analysis
   - Market research data sales

This dual-purpose model is concerning because users believe they're only installing an ad blocker, not participating in advertising data collection.

## Comparison to Fake Ad Blockers

**SBlock is NOT a fake ad blocker like smartadblocker.com network because:**

✓ Provides real ad blocking via declarativeNetRequest
✓ Has thousands of legitimate blocking rules
✓ Blocks ads on most websites effectively
✓ Includes element picker and advanced features

**However, it differs from ethical ad blockers (uBlock Origin, AdGuard) because:**

✗ Collects detailed advertising metadata
✗ Scrapes Facebook targeting/demographic data
✗ Transmits data to third-party servers
✗ Does not disclose data collection in privacy policy
✗ Uses obfuscated code to hide collection mechanisms

## Disclosure Issues

The Chrome Web Store description states: "Block ads and pop-ups on All the websites you browse every day"

**No mention of:**
- Data collection from social media platforms
- Ad metadata scraping
- Transmission to addon.sblock.pro
- Advertising intelligence gathering
- Use of Facebook GraphQL API for targeting data

## Recommendations

### For Users:
- **Uninstall if privacy-conscious** - The undisclosed data collection violates user expectations
- **Use alternatives** like uBlock Origin or AdGuard which don't collect data
- Users who browsed Facebook while this extension was active had their ad targeting preferences collected

### For Chrome Web Store:
- **Require disclosure** of advertising intelligence collection
- **Review privacy policy** for accuracy (likely omits data collection)
- **Verify compliance** with CWS policy against deceptive practices

### For the Developer:
- Add transparent disclosure of data collection in store listing
- Provide opt-out mechanism for intelligence collection
- Update privacy policy to detail what data is collected and why
- Consider making ad intelligence optional/separate from blocking

## Technical Details

### Endpoints
- `addon.sblock.pro/api/v1/external/data` - Ad intelligence collection
- `addon.sblock.pro/api/v1/external/resource` - Dynamic script loading
- `sblock.pro/uninstall` - Uninstall tracking
- `sblock.pro/thank-you-page` - First install tracking

### Permissions Usage
- `<all_urls>` - Required for ad blocking, but also enables scraping
- `declarativeNetRequest` - Legitimate ad blocking
- `scripting` - Content script injection for blocking AND scraping
- `storage` - Legitimate (stores user preferences)
- `unlimitedStorage` - Potentially stores large amounts of scraped data

### Code Obfuscation
The main background.js is heavily minified making reverse engineering difficult. Variable names like `V`, `O`, `A`, `F`, `M` hide the true purpose of functions.

## Conclusion

**Risk Level: MEDIUM**

SBlock is a functional ad blocker that provides value to users, but operates an undisclosed advertising intelligence operation that scrapes sensitive ad targeting data from Facebook and other platforms. While not technically malware, the lack of transparency around data collection represents a significant privacy violation.

The extension sits in a gray area - it's not a scam (it blocks ads as promised), but it extracts value from users beyond what they consented to. The 900K+ users are unknowingly participating in an ad intelligence network.

**Verdict:** Privacy violation through undisclosed data collection, but not a fake ad blocker or traditional malware.
