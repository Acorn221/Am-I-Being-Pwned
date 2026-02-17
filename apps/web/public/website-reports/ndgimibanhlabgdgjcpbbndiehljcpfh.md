# Security Analysis Report: SelectorsHub

**Extension ID:** ndgimibanhlabgdgjcpbbndiehljcpfh
**Extension Name:** SelectorsHub
**Version:** 5.6.2
**User Count:** 400,000
**Risk Level:** LOW

## Executive Summary

SelectorsHub is a developer tools extension for generating XPath, CSS selectors, and Playwright locators. While the static analyzer flagged 2 exfiltration flows (risk_score=60), code review reveals these are false positives related to the extension's advertised AI-powered selector fixing feature and standard usage analytics. The extension sends minimal, non-sensitive telemetry (button clicks, feature usage events) to disclosed analytics endpoints. The developer publicly claims zero personal data collection and local-only operation, which aligns with observed behavior.

**Final Assessment:** LOW risk - standard analytics for a developer tool with disclosed data practices.

---

## Risk Assessment

### Overall Risk: LOW

**Rationale:**
- Developer publicly discloses that the extension "doesn't collect any information and runs in your local machine only"
- Analytics endpoints receive only generic usage events (e.g., "open extension", "Copy xpath", "text checkbox")
- No collection of page content, DOM elements, user-generated selectors, or browsing data
- Legitimate tool functionality (selector generation, AI-assisted fixing) with appropriate permissions
- Developer provides public FAQ addressing privacy/security concerns

---

## Detailed Findings

### 1. Analytics & Telemetry (LOW)

**Description:**
The extension implements usage analytics via two endpoints:
- `https://shubads.testcasehub.net/analytics/ads/track`
- `https://selectorshub.info/nodeapp/api/link/track`

**Evidence:**
```javascript
// devtools-script.js:368
function trackEvent(a) {
  "string" !== typeof a &&
  fetch(`${API_URL}analytics/ads/track`, {
    method: "post",
    headers: {"Content-Type": "application/json"},
    body: JSON.stringify(a)
  })
}

// Example calls:
trackEvent("open extension");
trackEvent("Copy xpath");
trackEvent("text checkbox");
trackEvent("Right Toggle");
trackEvent("contextmenu: " + a.value);
```

**Data Sent:**
- Generic feature usage strings (button names, actions)
- No DOM content, selectors, URLs, or personal data observed
- Country/timezone detection via `Intl.DateTimeFormat().resolvedOptions().timeZone` for localization (not sent to server in reviewed code)

**Impact:**
This is standard usage telemetry for a commercial developer tool. The data collection is minimal and does not include sensitive information. While not explicitly detailed in a privacy policy link, the developer states on their website that the extension "runs offline and no data is saved on cloud."

**Severity:** LOW
**Recommendation:** Users should be aware of basic analytics. For privacy-sensitive environments, users can inspect network traffic or use the Pro version which may have clearer disclosures.

---

### 2. AI-Powered Selector Fixing Feature

**Description:**
The extension offers an AI-powered "Fix Selector" feature that sends invalid selectors to a GPT endpoint for correction.

**Evidence:**
```javascript
// devtools-script.js:29-30
fixSelectorBtn.addEventListener("click", async () => {
  const c = await fetch(API_URL + "gpt/fixpath", {
    method: "POST",
    headers: {"Content-Type": "application/json"},
    body: JSON.stringify({
      xpath: selectorInput.value,
      xpathOrCss: a
    })
  });
  // ...
});
```

**Endpoint:** `https://shubads.testcasehub.net/gpt/fixpath`

**Data Sent:**
- User-entered XPath/CSS selector (only when "Fix Selector" button is clicked)
- Selector type (xpath or css)

**Impact:**
This is an opt-in feature (user must click "Fix Selector" button). The selector strings themselves are technical locators (e.g., `//div[@id='main']`) and typically do not contain sensitive data. However, in rare cases, selectors could reference sensitive element IDs or text content.

**Severity:** LOW
**Recommendation:** Users working with sensitive data should avoid using the "Fix Selector" feature, or review selectors before submission.

---

### 3. False Positive: "Exfiltration Flows"

**Static Analyzer Findings:**
```
EXFILTRATION (2 flows):
  [HIGH] document.getElementById → fetch    devtools-panel/devtools-script.js
  [HIGH] document.querySelectorAll → fetch    devtools-panel/devtools-script.js
```

**Analysis:**
The static analyzer detected data flows from DOM access methods (`getElementById`, `querySelectorAll`) to `fetch()` calls. However, code inspection reveals:

1. **DOM access is for UI state, not page content:**
   The extension operates as a DevTools panel and side panel. DOM queries target the extension's own UI elements (buttons, input fields, version numbers):
   ```javascript
   // devtools-script.js:369
   const c = document.querySelector("#version");
   c && (c.innerText = `v${b.version}`);
   ```

2. **Fetch calls send only analytics events:**
   No code path was found where page DOM content (from the inspected tab) is sent to remote servers. The extension uses `chrome.devtools.inspectedWindow.eval()` and message passing to interact with the inspected page, but this data remains local.

**Conclusion:** These are false positives. The extension's DevTools panel UI queries its own DOM and sends unrelated analytics events.

---

## Permissions Analysis

| Permission | Justification | Risk |
|------------|---------------|------|
| `<all_urls>` | Required for DevTools to inspect any page | Standard for dev tools |
| `tabs` | Needed to inject content scripts and communicate with inspected page | Legitimate |
| `storage` | Saves user preferences (e.g., checkbox states, driver commands) | Legitimate |
| `cookies` | Sets authentication cookie for extension features | Low risk (scoped to selectorshub.com) |
| `clipboardWrite` | Copy selectors to clipboard (core functionality) | Legitimate |
| `contextMenus` | Right-click menu for copying selectors | Legitimate |
| `sidePanel` | Side panel UI (MV3 feature) | Legitimate |

**Assessment:** All permissions are appropriate for a DevTools extension generating selectors.

---

## Code Quality & Security Practices

### Strengths:
- No dynamic code execution (eval, Function constructor) on user data
- Uses message passing for content script communication
- Implements cookie authentication for premium features
- Standard Chrome Extension architecture (MV3)

### Weaknesses:
- Minified/obfuscated code (flagged by analyzer) makes manual review difficult
- No Content Security Policy in manifest
- Large codebase (~60K+ lines in devtools-script.js) increases attack surface
- Fetches ads configuration from remote server (not a security issue, but worth noting)

---

## Third-Party Integrations

1. **Analytics:** `shubads.testcasehub.net`
2. **API:** `selectorshub.info/nodeapp/api/`
3. **AI Features:** `shubads.testcasehub.net/gpt/fixpath`

All endpoints are owned by the developer (SelectorsHub/TestCaseHub). No third-party trackers detected.

---

## Recommendations

### For Users:
1. **General Use:** Safe for typical development work. Analytics is minimal and non-invasive.
2. **Enterprise/Sensitive:** Inspect network traffic if working with confidential data. Consider disabling analytics via firewall rules.
3. **Offline Use:** The core selector generation works offline. Avoid "Fix Selector" feature for airgapped environments.

### For Developers:
1. Publish a clear, detailed privacy policy on the Chrome Web Store listing
2. Provide opt-out mechanism for analytics
3. Consider open-sourcing the codebase to increase trust
4. Add CSP headers in manifest

---

## Compliance & Privacy

**Privacy Claim vs. Reality:**
- **Claim:** "Doesn't collect any information and runs in your local machine only" ([source](https://selectorshub.com/is-it-safe-and-secure-to-use-selectorshub/))
- **Reality:** Extension sends usage analytics (button clicks, feature names) but does NOT collect page content, selectors, URLs, or browsing history. The claim is mostly accurate but oversimplified.

**Data Minimization:** Good - only feature usage events are transmitted.
**User Control:** Limited - no in-extension toggle for analytics.
**Transparency:** Moderate - public FAQ addresses privacy but lacks formal policy in extension listing.

---

## Conclusion

SelectorsHub is a legitimate developer tool with minimal privacy impact. The static analyzer's "exfiltration flow" warnings are false positives caused by the extension querying its own UI DOM while also making unrelated analytics calls. The extension's data collection is limited to anonymous usage telemetry, consistent with industry standards for freemium developer tools. Users working in high-security environments should audit network traffic, but for typical development use, the extension poses LOW risk.

**No critical vulnerabilities identified.**

---

## Evidence Summary

| Finding | Severity | Evidence Location |
|---------|----------|-------------------|
| Usage analytics | LOW | `devtools-script.js:368`, `background.js:7` |
| AI selector fixing (opt-in) | LOW | `devtools-script.js:29-30` |
| False positive: exfil flows | N/A | Static analysis artifact |

---

## Metadata

- **Analysis Date:** 2026-02-15
- **Analyzer:** ext-analyzer (Babel AST) + manual code review
- **Extensions Version:** 5.6.2
- **Static Risk Score:** 60 (recalibrated)
- **Manual Risk Assessment:** LOW
- **Recommendation:** Safe for general use with awareness of analytics

---

## References

1. [SelectorsHub Safety FAQ](https://selectorshub.com/is-it-safe-and-secure-to-use-selectorshub/)
2. [Chrome Web Store Listing](https://chromewebstore.google.com/detail/selectorshub/ndgimibanhlabgdgjcpbbndiehljcpfh)
3. Static analysis: ext-analyzer v1.0
4. Source code: `/devtools-panel/devtools-script.js`, `/extension/background.js`
