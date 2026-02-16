# Vulnerability Report: Screen Shader | Smart Screen Tinting

## Metadata
- **Extension ID**: fmlboobidmkelggdainpknloccojpppi
- **Extension Name**: Screen Shader | Smart Screen Tinting
- **Version**: 2.1.1
- **Users**: ~600,000
- **Manifest Version**: 3
- **Analysis Date**: 2026-02-15

## Executive Summary

Screen Shader is a legitimate productivity extension designed to reduce eye strain by applying color tints to web pages. The extension applies a customizable color overlay using CSS mix-blend-mode, with automatic adjustment based on time of day (day/night/sleep cycles). While it requests broad permissions including `<all_urls>` and `scripting`, these are required for its core functionality of injecting visual overlays on all pages. The extension optionally uses geolocation data via www.geoplugin.net to calculate sunrise/sunset times for automatic shade adjustment, but this is user-initiated and clearly disclosed in the UI.

After thorough analysis, no security vulnerabilities, privacy violations, or malicious behavior patterns were identified. The extension functions exactly as described and does not collect, exfiltrate, or misuse any user data.

## Vulnerability Details

No vulnerabilities found.

## False Positives Analysis

### 1. Geolocation API Access
**Pattern**: The extension fetches location data from www.geoplugin.net in both background.js and popup.js.

**Why it's benign**:
- This is entirely optional and user-initiated via the "Auto-find location" button in the popup UI
- Used solely to calculate sunrise/sunset times for automatic shade transitions
- Location data is stored locally in chrome.storage and never sent to any third-party servers
- The extension falls back to timezone offset if location isn't available
- Code at background.js:84 and popup.js:1725 shows the fetch is only for reading GeoIP data, not sending any user information

### 2. Content Script on All URLs
**Pattern**: Content script runs on `<all_urls>` with `document_start` timing and `all_frames: true`.

**Why it's benign**:
- This is the core functionality - the extension must inject a screen overlay on every page
- The content script only manipulates the DOM to insert a `<screen-shader>` element with color overlays
- No data extraction or monitoring occurs
- Excludes advertising/tracking domains (googlesyndication.com, doubleclick.net, etc.) to avoid breaking ads

### 3. Broad Host Permissions
**Pattern**: Requests `file:///*` and `<all_urls>` host permissions.

**Why it's benign**:
- Required to shade all web pages including local files
- MV3 requires explicit host_permissions declaration
- Used only for content script injection, not network requests

### 4. Scripting Permission
**Pattern**: Uses `chrome.scripting.executeScript` in background.js:399.

**Why it's benign**:
- Only used during installation to inject the content script into existing tabs
- Does not execute arbitrary code - only injects the bundled content.js file
- This is a standard pattern for MV3 extensions to initialize on install

## API Endpoints Analysis

| Endpoint | Purpose | Data Sent | Data Received | Risk |
|----------|---------|-----------|---------------|------|
| www.geoplugin.net/json.gp | GeoIP location lookup | None (HTTP GET) | User's approximate location (city, country, lat/long) | NONE - User-initiated, optional feature for sunrise/sunset calculation |

## Code Analysis

### Background Script (background.js)
- **Primary Functions**:
  - Settings management and storage synchronization
  - Icon state updates based on enabled/disabled status
  - Keyboard shortcut handling for toggling/adjusting shade
  - Optional GeoIP lookup for sunrise/sunset calculation
  - Tab lifecycle management

- **Key Security Observations**:
  - No tracking or analytics code
  - No external network requests except optional GeoIP (lines 84-115)
  - No message passing to external domains
  - Uses complex astronomical calculations for sunrise/sunset (lines 234-259)

### Content Script (content.js)
- **Primary Functions**:
  - Injects `<screen-shader>` custom element containing overlay divs
  - Applies color tints using CSS mix-blend-mode
  - Calculates shade intensity based on time and sun position
  - Monitors fullscreen changes to move overlay appropriately
  - Custom scrollbar styling to match shade colors

- **Key Security Observations**:
  - Only manipulates DOM for visual overlay - no data access
  - Site-specific fixes for compatibility (Vanguard, Reddit, YouTube)
  - High z-index management to keep overlay on top
  - No message passing except checking if extension is enabled (line 711)

### Popup Script (popup.js)
- **Primary Functions**:
  - User interface for shade/darkness/color configuration
  - Location search and manual lat/long input
  - Preset shade configurations
  - Live preview of settings
  - Custom color picker

- **Key Security Observations**:
  - Uses chrome.tabs API only for opening settings pages and sending preview messages
  - Optional GeoIP fetch on user button click (line 1725)
  - No automatic data collection

## Overall Risk Assessment

**RISK LEVEL: CLEAN**

**Justification**:
Screen Shader is a well-designed, legitimate browser extension that performs exactly as advertised. While it requests broad permissions (`<all_urls>`, scripting, tabs, storage), these are all justified and necessary for its core functionality of applying visual overlays to reduce eye strain. The optional geolocation feature is transparent, user-initiated, and used solely for calculating sunrise/sunset times.

The extension demonstrates good coding practices:
- Extensive site-specific compatibility fixes
- Proper permission scoping
- No unnecessary network access
- Clear user consent for optional features
- No tracking, analytics, or data exfiltration

There are no security vulnerabilities, privacy violations, or indicators of malicious intent. This extension is safe for user installation.
