# Vulnerability Report: Skip Ads - Adblocker for YouTube

## Metadata
- **Extension ID**: lkahpjghmdhpiojknppmlenngmpkkfma
- **Extension Name**: Skip Ads - Adblocker for YouTube
- **Version**: 1.1.5
- **Users**: ~80,000
- **Manifest Version**: 3
- **Analysis Date**: 2026-02-15

## Executive Summary

Skip Ads - Adblocker for YouTube is a YouTube ad automation extension that automatically clicks skip buttons, fast-forwards ads, mutes ad audio, and hides ad-related DOM elements. The extension tracks the number of ads blocked locally and opens install/uninstall tracking URLs on ytskip.com. The extension implements standard ad-blocking functionality with minimal privacy concerns.

The extension uses `<all_urls>` host permissions and injects a content script on all websites, but functionally only operates on YouTube domains. The static analyzer found no exfiltration flows, code execution vulnerabilities, or attack surface issues. The ytskip.com endpoint is used only for install tracking and optional remote configuration updates.

## Vulnerability Details

No security or privacy vulnerabilities were identified.

## False Positives Analysis

**Install/Uninstall Tracking URLs**: The extension opens `https://ytskip.com/api/install` on installation and sets `https://ytskip.com/uninstall/` as the uninstall URL. This is standard analytics behavior for free extensions and is disclosed in the privacy policy (if one exists). The install endpoint is opened in a visible tab, not hidden.

**Remote Configuration**: The extension fetches `https://ytskip.com/siteSettings.json` on installation to retrieve settings with version checking. This is a legitimate remote configuration pattern. The settings are stored in `chrome.storage.local` and appear to control extension behavior. There is no evidence of malicious remote code execution or dynamic script injection.

**`<all_urls>` Content Script**: While the content script is declared to run on all URLs, the extension only functionally operates on YouTube domains. The content script checks for YouTube-specific selectors and would be inert on non-YouTube sites. This is overly broad but not malicious.

**Badge Counter and Statistics**: The extension tracks ad-blocking statistics locally (total ads blocked, per-domain counts, historical data). This data is stored in `chrome.storage.local` and `chrome.storage.sync` but is not sent to any external server beyond the initial install ping.

## API Endpoints Analysis

| Endpoint | Purpose | Data Sent | Risk |
|----------|---------|-----------|------|
| ytskip.com/api/install | Install tracking | Extension opens URL on install (via chrome.tabs.create) | LOW - Standard analytics, user-visible tab |
| ytskip.com/uninstall/ | Uninstall tracking | Opens on uninstall | LOW - Standard analytics |
| ytskip.com/siteSettings.json | Remote configuration | Fetches JSON settings with version check | LOW - Read-only config, no sensitive data sent |

## Overall Risk Assessment

**RISK LEVEL: LOW**

**Justification**: The extension provides legitimate ad-skipping functionality for YouTube with minimal privacy implications. The install/uninstall tracking is standard for free extensions. The remote configuration mechanism is benign (read-only settings fetch with no code execution). The extension does not exfiltrate browsing history, inject affiliate links, or perform any malicious actions. The only minor concern is the overly broad `<all_urls>` permission when the extension only needs YouTube domains, but this is a common over-privileging issue rather than a security vulnerability.
