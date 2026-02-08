# Vulnerability Report: Surfe.be Extension

## Metadata
- **Extension Name**: Surfe.be — the extension with which you earn
- **Extension ID**: manjolceoachljppbjhfgkoomnlidkna
- **Version**: 1.8.2
- **User Count**: ~60,000
- **Manifest Version**: 3
- **Analysis Date**: 2026-02-07

## Executive Summary

Surfe.be is a "paid-to-surf" browser extension that monetizes user browsing by displaying advertisements and directing users to visit specific websites in exchange for micropayments. The extension implements a legitimate business model common in the advertising/rewards space. While the extension's core functionality is not inherently malicious, it exhibits several concerning behaviors that raise privacy and security concerns:

1. **Comprehensive User Tracking**: The extension tracks clicks, mouse movements, and scroll events across all websites (excluding webmail services) and transmits this data to external servers without explicit consent mechanisms visible in the code.

2. **Broad Content Injection**: Injects advertisement panels and notification overlays on virtually all websites users visit, with limited exclusions for email services only.

3. **Tab Control and Navigation Manipulation**: The background service worker can create tabs, navigate users to specific URLs, and monitor navigation events as part of the "paid visits" workflow.

4. **Cross-Site Data Collection**: Collects and base64-encodes URLs of visited pages and sends them to backend servers.

The extension appears to be operating within its stated purpose (reward users for viewing ads/sites), but the scope of data collection and DOM manipulation warrants a **MEDIUM** risk classification due to privacy implications and the potential for abuse if backend infrastructure is compromised.

## Vulnerability Details

### 1. Comprehensive User Behavior Tracking
**Severity**: MEDIUM
**Files**: `content/track.js`
**Lines**: 1-97

**Description**:
The extension implements an aggressive tracking system that monitors user interactions across all websites:

```javascript
document.addEventListener('click', function(e) {
    if( !e.isTrusted ) return;
    tracker.pxl({
        ts: parseInt( e.timeStamp / 1000 ),
        u: tracker.uid,
        e: 1,
        v: e.target.href ? 1 : 0,
    });
});

document.addEventListener('scroll', function(e) {
    if( !e.isTrusted ) return;
    tracker.scroll++;
});

document.addEventListener('mousemove', function(e) {
    if( !e.isTrusted ) return;
    tracker.cursor++;
});
```

The tracker aggregates mouse movements and scroll events every 5 seconds and transmits them to `surfe.pro/track/` via pixel tracking:

```javascript
tracker.pxl({
    ts: parseInt( ((new Date()).valueOf() - tracker.start_at)/1000 ),
    u: tracker.uid,
    e: event,
    v: val,
});
```

**Privacy Impact**:
- Collects granular behavioral data (click patterns, scrolling frequency, mouse activity)
- Transmitted to `surfe.pro` domain separate from main `surfe.be` domain
- No visible opt-out mechanism in code
- Data could be used for detailed user profiling and behavior analysis

**Verdict**: This constitutes extensive behavioral tracking that goes beyond what's necessary for ad delivery. While not actively malicious, it represents significant privacy overreach for a rewards extension.

---

### 2. Universal Content Script Injection with DOM Manipulation
**Severity**: MEDIUM
**Files**: `manifest.json`, `content/content.js`
**Lines**: manifest.json:18-47, content.js:477-617

**Description**:
The extension injects content scripts on `<all_urls>` with only minimal exclusions for webmail services:

```json
"matches": ["<all_urls>"],
"exclude_matches": [
    "file:///*",
    "ftp://*/*",
    "*://mail.google.com/*",
    "*://mail.yandex.ru/*",
    "*://mail.yandex.ua/*",
    "*://mail.yandex.kz/*",
    "*://e.mail.ru/*",
    "*://mail.protonmail.com/*"
]
```

The content script creates persistent DOM overlays for advertisements and notifications:

```javascript
panel: function (d) {
    if (!$('#justroll').length) {
        var panel_node = $('<div>').attr('id', 'justroll').addClass(panel_class)
        panel_node.append($('<div>')
            .attr('id', 'justroll-panel-close')
            .attr('class', 'justroll-panel-btn')
            .attr('title', chrome.i18n.getMessage('hidePanel'))
            .html('&times;')
        )
        // ... additional controls
        panel_node.append($('<div>').attr('id', 'justroll-adv'))
        $('body').append(panel_node)
    }
}
```

**Privacy/Security Impact**:
- Operates on banking websites, healthcare portals, and other sensitive domains
- Can inject arbitrary HTML content received from backend servers
- Uses jQuery and DOMPurify for sanitization, which is good practice
- Modifies user experience across entire browsing session

**Verdict**: Broad injection scope is excessive but necessary for the business model. Sanitization with DOMPurify mitigates XSS risks. However, the extension should exclude financial and healthcare domains.

---

### 3. Tab Control and Forced Navigation
**Severity**: MEDIUM
**Files**: `service_worker.js`
**Lines**: 68-116, 349-442

**Description**:
The extension can programmatically create tabs and navigate users to specific URLs as part of the "paid visits" workflow:

```javascript
const visitStart = async (vsid, tabId) => {
    const endpoint = 'https://' + domain + '/ext-v2/task-start?ver=' + version + '&vsid=' + vsid

    const visitStartHandler = async (visit) => {
        visit = JSON.parse(visit)
        const task = {
            active: true,
            url: visit.url,
            timer: visit.time,
            captcha: visit.captcha,
            tabId: tabId,
            // ...
        }
        await ChromeStorage.set({ task })
        chrome.tabs.update(tabId, { url: task.url })
    }

    ajax(endpoint, null, visitStartHandler)
}
```

The extension monitors user focus, tab visibility, and can require users to keep tabs active and focused:

```javascript
if (task.flow || (response.focused == true && tab.active == true)) {
    task.timer -= 0.5
    await ChromeStorage.set({ task })
    // ... continue task
} else {
    setBadge(parseInt(task.timer), '#FA0')
}
```

**Security Impact**:
- Users can be directed to arbitrary URLs provided by backend
- Extension monitors whether tabs are focused/active
- Implements timer verification to ensure users view content for required duration
- Could potentially direct users to malicious sites if backend is compromised

**Verdict**: This is core functionality for the business model (paid visits), but creates significant risk if backend servers are compromised or if malicious actors gain access to the visit scheduling system.

---

### 4. Cross-Site URL Collection and Transmission
**Severity**: MEDIUM
**Files**: `libs/RequestHandler.js`, `service_worker.js`
**Lines**: RequestHandler.js:16-19, 66-68

**Description**:
The extension collects URLs of visited pages and transmits them (base64-encoded) to backend servers:

```javascript
let post = {}
if ('url' in sender) post['href'] = btoa(sender.url)

ajax(
    'https://' + this.domain + '/ext-v2/auth?ver=' + this.version,
    post,
    async (d) => {
        // ...
    }
)
```

This occurs during authentication and initialization requests, meaning the backend receives a log of URLs where the extension activates.

**Privacy Impact**:
- Backend servers can build a profile of user browsing habits
- Base64 encoding provides minimal obfuscation (easily reversible)
- No indication this data is anonymized or has retention limits
- Transmitted alongside user tokens for correlation

**Verdict**: URL collection is excessive for an ad-display extension and represents significant privacy exposure. Users should be explicitly informed of this behavior.

---

### 5. Video Player Manipulation
**Severity**: LOW
**Files**: `content/content.js`
**Lines**: 860-916

**Description**:
For video-based tasks (type 6), the extension can manipulate video player elements:

```javascript
if (videoPlayer
    && !videoPlayer.loop
    && videoPlayer.readyState > 2
    && document.querySelector('.ad-interrupting') === null) {
    videoPlayer.loop = true
}
```

The extension monitors video state (paused, muted, viewport visibility) and enforces viewing requirements for paid video tasks.

**Verdict**: Legitimate functionality for video-based rewards, but could interfere with normal video viewing experience. Not a security concern.

---

### 6. Remote Configuration and Kill Switch
**Severity**: LOW
**Files**: `service_worker.js`
**Lines**: 444-471

**Description**:
The extension fetches a "stop list" of domains/pages where it should not activate:

```javascript
const isStopListed = (url) => {
    let stopList = cm.get('stopList')
    if (!stopList) {
        ajax('https://' + domain + '/ext/get-stop-list?ver=' + version, null, function (resp) {
            cm.set('stopList', resp, 3600)
            stopList = JSON.parse(resp)
        })
        return true
    }
    // ... check if URL matches stopList
}
```

**Security Impact**:
- Backend can remotely control where extension operates
- Positive: Allows developers to exclude sensitive domains reactively
- Negative: Could be abused to selectively disable extension on detection/analysis domains

**Verdict**: Remote configuration is common practice and not inherently malicious. However, there's no code signing or integrity verification of the stop list.

---

## False Positive Analysis

| Pattern | File | Context | Verdict |
|---------|------|---------|---------|
| jQuery usage | libs/jquery.min.js | Standard jQuery 3.x library | **SAFE** - Legitimate dependency |
| DOMPurify | popup/purify.js | DOMPurify sanitization library | **SAFE** - Used for XSS prevention |
| btoa() encoding | libs/RequestHandler.js | Base64 encode URLs before transmission | **BENIGN** - Obfuscation, not encryption |
| Video loop modification | content/content.js | Loops video for paid viewing tasks | **EXPECTED** - Part of business model |
| Tab focus monitoring | service_worker.js | Ensures users view paid content | **EXPECTED** - Required for rewards verification |
| postMessage listeners | content/content.js | Receives auth callbacks from popup windows | **SAFE** - Proper origin checking |

## API Endpoints and Data Flow

### Primary Domain: surfe.be
| Endpoint | Method | Purpose | Data Sent |
|----------|--------|---------|-----------|
| `/ext-v2/auth` | POST | User authentication | `href` (base64 URL), version |
| `/ext/init` | POST | Initialize ad panel | `token`, `href` (base64 URL) |
| `/ext/balance` | POST | Fetch user balance | `token`, `href` |
| `/ext-v2/task-start` | POST | Start paid visit task | `vsid` (visit session ID) |
| `/ext-v2/task-complete` | POST | Complete paid visit | `key` (task key), captcha solution |
| `/ext-v2/task-skip` | POST | Skip failed task | `key` |
| `/ext-v2/popup` | POST | Load popup UI | `task` (boolean), version |
| `/ext/hide` | POST | Hide ads on specific sites | `type`, `val` (host/URL/ad ID) |
| `/ext/get-stop-list` | POST | Fetch blocked domains list | version |
| `/ext/banner` | GET | Fetch ad banner image | `key` (banner key) |
| `/ext/click` | GET | Track ad click | `id` (banner ID) |
| `/ext/video-rated` | POST | Report video rating | `bid` (video ID) |
| `/ext/direct-auth` | GET | OAuth-style authentication | version |

### Secondary Domain: surfe.pro
| Endpoint | Method | Purpose | Data Sent |
|----------|--------|---------|-----------|
| `/track/{sid}` | GET (pixel) | Behavioral tracking | `ts` (timestamp), `u` (user ID), `e` (event type), `v` (event value) |

### Third-Party Domain: captcha.surfe.be
| Endpoint | Method | Purpose | Data Sent |
|----------|--------|---------|-----------|
| `/collage/preview.php` | POST | Fetch captcha image | `token`, `lang`, `w` (width), `h` (height) |

## Data Flow Summary

```
User Browsing
    ↓
Content Script (all websites)
    ├── Tracks: clicks, scrolls, mouse movements → surfe.pro/track/
    ├── Collects: URL, focus state, video player state
    ├── Displays: Ad panels, notifications, captchas
    └── Sends: User interactions → Backend API
         ↓
Service Worker
    ├── Authenticates user → /ext-v2/auth (sends URL)
    ├── Fetches ads/tasks → /ext/init
    ├── Controls tabs → Creates/navigates for paid visits
    ├── Monitors tasks → Validates viewing time/focus
    └── Reports completion → /ext-v2/task-complete
         ↓
Backend Servers (surfe.be)
    ├── User profile & balance
    ├── Ad inventory & task queue
    ├── Browsing history (URLs)
    └── Behavioral analytics
```

**Key Privacy Concerns**:
1. **Browsing History**: Backend receives base64-encoded URLs during auth/init
2. **Behavioral Profile**: Granular click/scroll/mousemove data sent to surfe.pro
3. **Task Compliance**: Extension monitors tab focus, video state, page load status
4. **Cross-Site Tracking**: User ID (`uid`) correlates activity across domains

## Overall Risk Assessment

**RISK LEVEL: MEDIUM**

### Risk Factors:
1. ✅ **No Dynamic Code Execution**: No `eval()`, `Function()`, or dynamic script injection
2. ✅ **Content Sanitization**: Uses DOMPurify to sanitize HTML from backend
3. ✅ **No Credential Harvesting**: Does not access passwords, form data, or cookies
4. ⚠️ **Excessive Tracking**: Monitors clicks, scrolls, mouse movements across all sites
5. ⚠️ **URL Collection**: Transmits visited URLs to backend servers
6. ⚠️ **Universal Injection**: Operates on all websites including sensitive domains
7. ⚠️ **Tab Control**: Can navigate users to arbitrary URLs from backend
8. ⚠️ **Backend Trust**: Security depends entirely on backend infrastructure integrity

### Comparison to Similar Extensions:
- **Honey/Rakuten**: Similar ad injection but more limited tracking
- **Brave Rewards**: More transparent about data collection and privacy-preserving
- **AdBlock Plus**: Acceptable Ads feature is less intrusive than forced navigation

### Potential Attack Vectors if Backend Compromised:
1. **Forced Phishing**: Malicious actors could inject phishing URLs into visit queue
2. **Data Exfiltration**: Enhanced tracking could capture sensitive user interactions
3. **Malvertising**: Ad content could be replaced with malicious payloads
4. **Clickjacking**: DOM manipulation could overlay legitimate site elements

### Recommendations for Users:
1. Only install if comfortable with comprehensive browsing tracking
2. Avoid using on financial, healthcare, or work-related websites
3. Review privacy policy at https://surfe.be/site/privacy-policy
4. Consider using in isolated browser profile for privacy compartmentalization

### Recommendations for Developers:
1. Implement explicit opt-in for behavioral tracking with clear disclosure
2. Exclude sensitive domain categories (banking, healthcare, government)
3. Add content security policy restrictions on injected content
4. Implement certificate pinning or code signing for remote configs
5. Anonymize or hash URLs before transmission to backend
6. Add user-visible dashboard showing collected data
7. Implement automatic data deletion after retention period

## Conclusion

Surfe.be is a legitimate paid-to-surf extension that operates within the boundaries of its stated functionality. However, it implements aggressive data collection practices that exceed what's necessary for ad delivery and reward distribution. The extension's security posture is reasonably sound with proper sanitization and no dynamic code execution, but the privacy implications are significant.

The **MEDIUM** risk classification reflects:
- ✅ No active malware or exploitation attempts detected
- ⚠️ Concerning privacy practices (tracking, URL collection)
- ⚠️ Potential for abuse if backend infrastructure is compromised
- ⚠️ Broad permissions and universal site access

Users should be fully aware that installing this extension grants comprehensive visibility into their browsing behavior to the Surfe.be service, and that the extension can programmatically control browser tabs and navigation.
