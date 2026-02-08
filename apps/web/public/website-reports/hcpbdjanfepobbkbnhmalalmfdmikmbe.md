# Vulnerability Report: Calculator Extension

## Metadata
- **Extension Name**: Calculator
- **Extension ID**: hcpbdjanfepobbkbnhmalalmfdmikmbe
- **Version**: 1.8.2
- **User Count**: ~90,000
- **Manifest Version**: 3
- **Analysis Date**: 2026-02-07

## Executive Summary

The Calculator extension is a simple calculator application that includes **dynamic remote content injection** from third-party servers. The extension fetches and renders HTML/JavaScript from `linangdata.com` endpoints without user consent, creating a potential attack vector for malicious content injection. While the current implementation appears benign (navigation links and banner ads), the architecture allows the remote server to inject arbitrary HTML/JavaScript into the extension's popup, which could be weaponized for:

- Ad/coupon injection
- Tracking user behavior
- Phishing attacks
- XSS exploitation

The extension has **zero permissions** in its manifest, which limits the damage potential, but the dynamic content loading pattern is a significant security anti-pattern.

**Risk Level**: MEDIUM

## Vulnerability Details

### VUL-001: Remote Dynamic Content Injection (MEDIUM)

**Severity**: MEDIUM
**Files**: `calculatorResponsive.js` (lines 24, 33, 44)
**CWE**: CWE-829 (Inclusion of Functionality from Untrusted Control Sphere)

**Description**:
The extension makes three AJAX requests to `linangdata.com` on popup load and injects the responses directly into the DOM using jQuery `.html()`:

```javascript
// Line 24-32
$.get(`https://linangdata.com/servedcontent/dynamiclinks.php?source=calculator&uuid=${uuid}`, function (data) {
  $("#links").html(data);
  $(".navopentab").unbind().on("click", function (e) {
    e.preventDefault();
    var link = $(this).attr('href');
    chrome.tabs.create({ url: link });
  })
});

// Line 33-43
$.get(`https://linangdata.com/servedcontent/bannertop.php?source=calculator&uuid=${uuid}`, function (data) {
  if (data) {
    $("#banner-top").html(data).removeClass('hidden');
  }
  // ... similar event binding
});

// Line 44-54
$.get(`https://linangdata.com/servedcontent/bannerbottom.php?source=calculator&uuid=${uuid}`, function (data) {
  if (data) {
    $("#banner-bottom").html(data).removeClass('hidden');
  }
  // ... similar event binding
});
```

**Verdict**: VULNERABLE - The extension allows a third-party server to inject arbitrary HTML/JavaScript into the popup context. While the extension has no permissions, this could be used for:
- Phishing attacks (fake UI elements)
- Tracking pixel injection
- Click-jacking via dynamically loaded links
- User fingerprinting via the UUID parameter

**Attack Scenario**:
1. Attacker compromises `linangdata.com` or performs DNS hijacking
2. Malicious HTML/JS is served from the endpoints
3. Extension injects content into ~90,000 users' browsers
4. Attacker can display phishing forms, tracking pixels, or malicious links

**Mitigation**: Remove dynamic content loading or implement Content Security Policy with strict-dynamic and nonces.

---

### VUL-002: UUID-Based User Tracking (LOW)

**Severity**: LOW
**Files**: `calculatorResponsive.js` (line 22)
**CWE**: CWE-359 (Exposure of Private Information)

**Description**:
The extension generates a timestamp-based UUID and sends it to `linangdata.com` servers:

```javascript
const uuid = new Date().getTime();
$.get(`https://linangdata.com/servedcontent/dynamiclinks.php?source=calculator&uuid=${uuid}`, ...)
```

**Verdict**: PRIVACY CONCERN - While not a direct vulnerability, this allows the remote server to track when users open the calculator popup. The UUID is not persistent (regenerated each time), but combined with IP addresses and browser fingerprinting, could enable user tracking.

---

### VUL-003: Lack of Content Security Policy (LOW)

**Severity**: LOW
**Files**: `manifest.json`
**CWE**: CWE-1188 (Insecure Default Initialization)

**Description**:
The manifest does not define a Content Security Policy, relying on default browser protections. This allows the dynamic content injection pattern to function.

**Verdict**: WEAK CONFIGURATION - A strict CSP would prevent the remote content injection, but its absence enables the attack surface described in VUL-001.

---

## False Positives

| Pattern | Location | Reason |
|---------|----------|--------|
| `math.eval()` | calculatorResponsive.js:636, 640, 644, 650, 772, 782, 788 | Legitimate use of math.js library for calculator operations. Input is controlled by user clicks, not arbitrary code execution |
| `localStorage` access | calculatorResponsive.js:377, 437 | Benign state persistence for calculator history and display values |
| jQuery `.html()` | calculatorResponsive.js:25, 35, 46 | **NOT A FALSE POSITIVE** - This is the vulnerability vector for remote content injection |

---

## API Endpoints

| Endpoint | Purpose | Data Sent | Risk |
|----------|---------|-----------|------|
| `https://linangdata.com/servedcontent/dynamiclinks.php` | Load navigation menu | `source=calculator`, `uuid={timestamp}` | MEDIUM - Allows arbitrary HTML injection |
| `https://linangdata.com/servedcontent/bannertop.php` | Load top banner ad | `source=calculator`, `uuid={timestamp}` | MEDIUM - Allows arbitrary HTML injection |
| `https://linangdata.com/servedcontent/bannerbottom.php` | Load bottom banner ad | `source=calculator`, `uuid={timestamp}` | MEDIUM - Allows arbitrary HTML injection |
| `https://linangdata.com/` | Navigation link | None | LOW - Hardcoded navigation |
| `https://linangdata.com/tools/` | Navigation link | None | LOW - Hardcoded navigation |
| `https://linangdata.com/calculator/` | Navigation link | None | LOW - Hardcoded navigation |
| `https://paypal.me/thankyoumuchlee/5` | Donation link | None | LOW - Hardcoded donation link |

---

## Data Flow Summary

1. **Popup Opens** → Extension generates timestamp UUID
2. **AJAX Requests** → Three GET requests to `linangdata.com/servedcontent/*` with UUID
3. **Remote Content Injection** → HTML/JS from server injected into popup DOM via `.html()`
4. **Event Binding** → Extension binds click handlers to open links in new tabs via `chrome.tabs.create()`
5. **Local Storage** → Calculator state (history, display values) stored in localStorage

**Data Exfiltration Risk**: LOW - Extension has no host permissions, cannot access page content, and doesn't transmit sensitive data (only timestamps).

**Supply Chain Risk**: MEDIUM - Dependency on `linangdata.com` availability and integrity. Server compromise = extension compromise.

---

## Overall Risk Assessment

**Risk Level**: **MEDIUM**

**Rationale**:
- The extension implements a **dangerous pattern** (remote content injection) that violates Chrome extension security best practices
- Current implementation appears benign (navigation links + banner ads)
- **Zero manifest permissions** significantly limits damage potential
- ~90,000 users exposed to supply chain risk via `linangdata.com` dependency
- No evidence of malicious behavior, but architecture enables future exploitation

**Recommendations**:
1. **Remove dynamic content loading** - Hardcode navigation links and remove banner ads
2. **Implement strict CSP** if dynamic content is required
3. **Use subresource integrity (SRI)** for external resources
4. **Monitor `linangdata.com`** for compromise indicators

**Comparison to Chrome Web Store Policies**:
- Violates best practices for remote code execution (even if HTML-only)
- Borderline violation of "One Purpose" policy if primary purpose is calculator but includes ad delivery
- No clear violation of existing policies, but risky architecture

---

## Technical Notes

- **No background scripts** - Extension is popup-only
- **No content scripts** - Cannot access or modify web pages
- **No host permissions** - Cannot make requests to arbitrary domains (except via popup context)
- **Libraries**: jQuery 3.5.1, Math.js, Bootstrap 5.0.1 (all legitimate, no tampering detected)
- **Obfuscation**: None - Code is readable and matches expected calculator functionality

---

## Conclusion

The Calculator extension provides legitimate functionality but implements a **security anti-pattern** that could be weaponized. The lack of permissions mitigates the risk, but ~90,000 users are exposed to potential phishing, tracking, or supply chain attacks if `linangdata.com` is compromised. Classification as **MEDIUM risk** is warranted due to the architectural vulnerability, though current behavior is benign.
