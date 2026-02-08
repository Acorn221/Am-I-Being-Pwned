# Vulnerability Report: Video Editor for Chromebook & more: Free

## Metadata
| Field | Value |
|-------|-------|
| Extension Name | Video Editor for Chromebook & more: Free (WeVideo) |
| Extension ID | okgjbfikepgflmlelgfgecmgjnmnmnnb |
| Version | 4.4.0 |
| Manifest Version | 2 |
| Users | ~4,000,000 |
| Type | Chrome Hosted App (not a traditional extension) |

## Executive Summary

This is a **Chrome Hosted App**, not a traditional browser extension. It contains **zero executable code** -- no JavaScript files, no HTML files, no background scripts, no content scripts, and no service workers. The entire extension is a thin launcher that redirects users to `http://www.wevideo.com/drive` (the WeVideo web application). It also declares itself as a Google Drive container app (`"container": "GOOGLE_DRIVE"`).

Because there is no code bundled in the extension itself, there is essentially no client-side attack surface. All logic resides on the remote WeVideo web servers, which is outside the scope of this extension-level analysis.

## Manifest Permissions Analysis

### Permissions Requested
- **None.** The manifest declares zero permissions.

### Content Security Policy
- **None declared.** Not needed since there is no executable content.

### Background Scripts
- **None.** No background page, background scripts, or service worker.

### Content Scripts
- **None.** No content scripts injected into any pages.

### Web Accessible Resources
- **None declared.**

### Host Permissions
- **None.** No access to any websites or tabs.

## Vulnerability Details

No vulnerabilities found. The extension contains no executable code to analyze.

## Minor Observations

| # | Observation | Severity | Details | Verdict |
|---|-------------|----------|---------|---------|
| 1 | HTTP launch URL | INFO | `web_url` uses `http://` instead of `https://` for `www.wevideo.com/drive`. In practice, browsers will likely upgrade this via HSTS, but the manifest should ideally specify HTTPS. | Not exploitable -- browser-level HSTS/redirect handles this. |
| 2 | `__MACOSX` artifacts | INFO | The CRX contains `__MACOSX/` directory artifacts from macOS ZIP creation. These are `desktop.ini` metadata files with no executable content. | Benign build artifact. |
| 3 | `desktop.ini` files | INFO | Windows `desktop.ini` files present throughout the package, likely from the build/packaging environment. | Benign build artifact. |

## False Positive Table

| Pattern | Location | Reason for FP Classification |
|---------|----------|------------------------------|
| N/A | N/A | No code to analyze -- no false positives to report |

## API Endpoints Table

| Endpoint | Purpose | Risk |
|----------|---------|------|
| `http://www.wevideo.com/drive` | App launch URL -- opens WeVideo web app | LOW (no data sent from extension; just a URL redirect) |
| `https://clients2.google.com/service/update2/crx` | Chrome Web Store auto-update URL | NONE (standard CWS update mechanism) |

## Data Flow Summary

There is no data flow within this extension. It contains no scripts that could read, process, or transmit data. When a user clicks the extension icon, Chrome simply navigates to the WeVideo website. All subsequent data handling occurs in the WeVideo web application context, not within the extension.

```
User clicks app icon --> Chrome navigates to http://www.wevideo.com/drive --> (end of extension involvement)
```

## Overall Risk Assessment

**CLEAN**

This extension is a Chrome Hosted App with zero bundled code, zero permissions, and zero client-side attack surface. It functions purely as a bookmark/launcher to the WeVideo web application. There is no malicious behavior, no data collection, no permission abuse, and no vulnerabilities to exploit. The only content in the package is the manifest, localization strings, an icon image, build artifacts, and Chrome Web Store metadata.
