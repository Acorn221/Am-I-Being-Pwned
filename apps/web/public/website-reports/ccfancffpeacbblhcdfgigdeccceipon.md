# Security Analysis: DrivePassword Password Manager

| Field | Value |
|-------|-------|
| Extension ID | `ccfancffpeacbblhcdfgigdeccceipon` |
| Version | 2.1.10 |
| Manifest Version | 3 |
| Users | ~1,000 |
| Risk | **CLEAN** |
| Date | 2026-02-09 |

## Summary

Minimal launcher extension that opens DrivePassword web app in a new tab; no content scripts, no data collection, no dynamic code execution.

## Vulnerabilities

No vulnerabilities found. This extension has an extremely small attack surface.

The extension consists solely of a background service worker (~490 lines including webpack boilerplate) that:
1. Opens `https://app.drivepassword.com` when the extension icon is clicked
2. Opens a "thank you" page on first install
3. Sets an uninstall URL on browser startup

There are no content scripts, no popup pages, no options pages, and no network requests beyond tab navigation.

---

### Note: Overly Broad Host Permissions

**Files:** `manifest.json`

```json
"host_permissions": ["*://*/*"]
```

**Analysis:** The extension requests `host_permissions` for all URLs, but declares no content scripts and does not use `chrome.scripting.executeScript` or any other API that would leverage these permissions. The broad host permission is unnecessary for the extension's actual functionality (opening a specific URL in a new tab). This is likely a leftover from development or a future-proofing measure. It does not pose a security risk in the current codebase since no code utilizes it.

**Verdict:** Informational -- overly broad but unused permission; no exploitable surface.

---

## Flags

No flags applicable. The extension does not exhibit any flaggable behavior.

| Category | Evidence |
|----------|----------|
| *(none)* | No flaggable patterns detected |

## False Positives

| Pattern | Location | Reason |
|---------|----------|--------|
| jQuery XHR | `js/libs/jquery.min.js` | Standard jQuery AJAX -- bundled library, not invoked by extension code |
| PapaParse XHR | `js/libs/papaparse.min.js` | Standard CSV parser download capability -- bundled library, not invoked |
| CryptoJS | `js/libs/crypto-js.js` | Standard crypto library -- bundled but not referenced by background.js |
| WAR `res/*` to `<all_urls>` | `manifest.json` | Only exposes PNG image assets (icons/logos), no JS or HTML |

## Endpoints

| Domain | Purpose | Data Sent |
|--------|---------|-----------|
| app.drivepassword.com | Main web app opened on icon click | None (tab navigation only) |
| beta.drivepassword.com | Configured in Config but not actively used | None |
| drivepassword.com | Install/uninstall landing pages | None (tab navigation only) |

## Data Flow

This extension collects and transmits no user data. Its entire data flow consists of:

1. **Local storage**: Stores a single `versn` key to track whether the extension has been installed (to show the welcome page only once) and a `dpdw` key for widget state. Both are stored in `chrome.storage.local` and never transmitted.

2. **Tab navigation**: Opens `https://app.drivepassword.com` when the user clicks the extension icon. Opens `https://drivepassword.com/thank-you-for-installing-extension/` on first install. Sets `https://drivepassword.com/uninstall-extension/` as the uninstall URL.

No user browsing data, credentials, cookies, history, or any other sensitive information is accessed or collected by this extension. The actual password management functionality exists entirely within the `app.drivepassword.com` web application, not within the extension itself.

## Overall Risk: CLEAN

DrivePassword Password Manager is essentially a bookmark launcher for the DrivePassword web application. Despite requesting broad `host_permissions` (`*://*/*`) and bundling several JS libraries (jQuery, CryptoJS, Materialize, PapaParse, PatternLock), the extension's actual code is minimal and benign. The service worker only handles three events: icon click (open web app), install (store version, show welcome page), and startup (set uninstall URL). There are no content scripts, no data collection, no dynamic code execution, no network requests, and no use of sensitive browser APIs. The bundled libraries appear to be remnants of a more feature-rich version or intended for future use, but are not loaded or executed in the current build. The web accessible resources only expose image files. This extension poses no security risk to users.
