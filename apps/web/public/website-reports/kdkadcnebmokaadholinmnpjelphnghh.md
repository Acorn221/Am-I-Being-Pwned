# Vulnerability Report: Canvas+ (kdkadcnebmokaadholinmnpjelphnghh)

**Extension:** Canvas+ v0.4.7
**Manifest Version:** 3
**Permissions:** `storage`, `*://*.instructure.com/*` (host), `<all_urls>` (optional)
**Analyst Date:** 2026-02-06
**Triage Flags:** V1=5, V2=4 -- innerhtml_dynamic, dynamic_tab_url, dynamic_window_open

## Executive Summary

Canvas+ is a Canvas LMS (Instructure) enhancement extension that adds dark mode, search, sidebar customization, conversation peeking, quiz refill, and smart scrolling features. The extension only runs on `*.instructure.com` origins.

After thorough analysis of all flagged patterns and complete code review, **no high-severity or actively exploitable vulnerabilities were found**. All innerHTML usages involve static content or extension-storage-controlled data. Dynamic URL navigation uses Canvas LMS API-sourced URLs which are server-generated and constrained to the same origin.

Two low-severity findings are documented below for completeness.

---

## Vulnerability 1: Unvalidated API-Sourced URL Navigation

**CVSS 3.1:** 3.1 (Low)
**Vector:** `CVSS:3.1/AV:N/AC:H/PR:L/UI:R/S:U/C:N/I:L/A:N`
**File:** `/src/inject/search/search.js` lines 933, 1078-1084, 1384
**Additional context:** `/src/inject/search/search.js` line 352

### Description

The search feature fetches course content from Canvas LMS API endpoints (`/api/v1/courses/{id}/modules?include=items`, `/api/v1/courses/{id}/pages`, `/api/v1/courses/{id}/assignments`). The `html_url` fields from these API responses are stored in `searchUI.results[].url` and later used directly in `window.open(urlToOpen)` and `location.href = urlToOpen` calls without URL scheme validation.

Specifically at line 352:
```javascript
} else if (
    moduleItem.type !== "Header" &&
    moduleItem.type !== "SubHeader"
) {
    itemUrl = moduleItem["html_url"];  // Used directly from API response
}
```

And at lines 1078-1084 (Enter key handler):
```javascript
} else if (event.key === "Enter") {
    const urlToOpen = searchUI.results[searchUI.selected].url;
    if (usingControlKey ^ searchUI.invertOpenNewTab) {
        window.open(urlToOpen);
    } else {
        location.href = urlToOpen;
    }
}
```

### PoC Exploit Scenario

1. An attacker would need to compromise the Canvas LMS API server or find a way to inject a malicious `html_url` field (e.g., `javascript:alert(document.cookie)`) into the Canvas API response for module items.
2. A Canvas+ user with the search feature enabled navigates to their Canvas instance.
3. The extension fetches module items and stores the malicious URL in the search index.
4. When the user searches and selects/clicks the result, `location.href` or `window.open()` is called with the attacker-controlled URL.

### Impact

Theoretical open redirect or JavaScript execution in the context of the Canvas LMS page. In practice, Canvas LMS API responses are server-generated and `html_url` values are absolute HTTPS URLs to the same Canvas instance. Exploitation would require a server-side vulnerability in Canvas LMS itself, making this a defense-in-depth issue rather than a directly exploitable flaw.

### Mitigation

Validate that `urlToOpen` uses `https:` or `http:` scheme before navigating, or use `new URL()` to parse and verify the origin matches the current `*.instructure.com` domain.

---

## Vulnerability 2: Remote Configuration Fetch Without Integrity Check

**CVSS 3.1:** 2.6 (Low)
**Vector:** `CVSS:3.1/AV:N/AC:H/PR:L/UI:R/S:U/C:N/I:L/A:N`
**File:** `/src/canvas.js` line 622

### Description

The extension fetches a remote configuration file from `https://canvasplus.org/remote.json` to determine survey rollout percentage:

```javascript
fetch("https://canvasplus.org/remote.json").then((remoteData) => {
    remoteData.json().then((remoteData) => {
        const seedPct = data["canvasplus-survey-seed-1"] ?? 0;
        const rolloutPct = remoteData["survey-1-rollout-pct"] ?? 0;
        if (seedPct >= rolloutPct) return;
        // ... triggers survey notification flow
    });
});
```

The fetched JSON is only used for a single numeric comparison (`survey-1-rollout-pct`). However, there is no integrity verification (e.g., Subresource Integrity, signature check) on the remote configuration. If `canvasplus.org` were compromised, the attacker could not directly inject code through this path (the value is used only in a numeric comparison), but it could force the survey UI to display for all users.

### PoC Exploit Scenario

1. Attacker compromises `canvasplus.org` or performs DNS hijacking.
2. Attacker sets `survey-1-rollout-pct` to `0` in `remote.json`.
3. All Canvas+ users would see the survey notification prompt on every Canvas LMS page load.

### Impact

Nuisance-level: forced display of the survey notification UI. No code execution, no data exfiltration. The survey itself links to a Google Forms URL that is hardcoded in the extension, not from the remote config.

### Mitigation

Pin the expected domain and validate the response schema. Consider removing the remote config dependency entirely since the survey appears to be a one-time feature.

---

## False Positive Analysis

The following triage flags were investigated and determined to be **not vulnerabilities**:

### innerHTML with Dynamic Content (FALSE POSITIVE)

| Location | Pattern | Why Not Vulnerable |
|----------|---------|-------------------|
| `canvas.js:57` | `popup.innerHTML` with template literal | Dynamic values are `selectedAppearance` from extension storage (self-controlled, not user input) and `chrome.runtime.getURL()` (safe by design). Values map to CSS classes ("selected"/"") and boolean attributes. |
| `search.js:1209` | `controlIcon.innerHTML = icon` | `icon` parameter is always a hardcoded SVG string literal passed from `buildControls()`. |
| `search.js:1309,1319,1331` | `headerElementIcon.innerHTML` | Set to hardcoded SVG string literals. No dynamic data. |
| `search.js:1354,1478` | `innerHTML = ""` | Used only to clear element content. |
| `sidebar.js:162,179,196,264` | Multiple `innerHTML` assignments | All set to hardcoded HTML/SVG button markup. No dynamic data interpolation. |
| `scroll.js:11` | `stub.innerHTML` | Static HTML template literal with no dynamic content. |
| `snackbar.js:57` | `innerHTML = ''` | Used only to clear container before appending new elements. |
| `popup.bundle.js`, `start.bundle.js` | React runtime innerHTML | Standard React runtime `dangerouslySetInnerHTML` property handling and SVG namespace workaround. Known framework false positive pattern. |

### Dynamic Tab/Window URLs (FALSE POSITIVE)

| Location | Pattern | Why Not Vulnerable |
|----------|---------|-------------------|
| `background.js:44` | `chrome.tabs.create({ url: "https://canvasplus.org/welcome" })` | Hardcoded URL on extension install. |
| `canvas.js:437` | `window.open("https://scorecardgrades.com")` | Hardcoded URL. |
| `sidebar.js:166,267` | `window.open(chrome.runtime.getURL(...))` | Opens extension-internal popup page. |
| `canvas.js:601` | `surveyFrame.src = url` (Google Forms URL) | URL built from extension storage values with `encodeURIComponent`. Loads in iframe. Values are self-controlled. |

---

## Overall Risk Assessment: **LOW**

Canvas+ is a benign educational utility extension. No malicious patterns, data harvesting, extension enumeration, or suspicious network activity were found. The two findings above are defense-in-depth recommendations, not actively exploitable vulnerabilities. The extension follows reasonable security practices for its scope, including MV3 architecture, minimal permissions, and use of `innerText`/`textContent` for user-facing dynamic content in most places.
