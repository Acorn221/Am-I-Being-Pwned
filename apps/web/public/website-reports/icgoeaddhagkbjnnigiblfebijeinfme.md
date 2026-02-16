# Vulnerability Report: YouTube Dark Theme

## Metadata
- **Extension ID**: icgoeaddhagkbjnnigiblfebijeinfme
- **Extension Name**: YouTube Dark Theme
- **Version**: 0.4.1
- **Users**: ~60,000
- **Manifest Version**: 3
- **Analysis Date**: 2026-02-15

## Executive Summary

YouTube Dark Theme is a legitimate extension that enables YouTube's native dark mode by manipulating the PREF cookie. The extension uses YouTube's official dark mode mechanism (f6=400 for dark, f6=80000 for light) and does not introduce any security or privacy vulnerabilities. All functionality is implemented locally with no external network requests, data collection, or tracking. The extension includes optional scheduling features to automatically switch between light and dark modes at specified times.

## Functionality Analysis

### Core Mechanism
The extension works by modifying YouTube's `PREF` cookie:
- **Dark mode**: Sets `f6=400` in the PREF cookie
- **Light mode**: Sets `f6=80000` in the PREF cookie
- This is YouTube's native theme switching mechanism, not a custom implementation

### Key Components

1. **Service Worker (worker.js)**
   - Manages cookie manipulation for theme switching
   - Implements scheduled dark/light mode switching based on time of day
   - Updates extension icon to reflect current state
   - Opens FAQ/support page on install/update (standard behavior)

2. **Content Script (data/inject.js)**
   - Injects custom CSS variables to customize colors
   - Uses CSS custom properties that YouTube's native dark mode supports
   - All styling is done via CSS injection, no DOM manipulation

3. **Options Page (data/options/index.js)**
   - Simple preference management
   - Allows customization of colors and scheduling
   - All preferences stored in chrome.storage.local (local only)

## Security Analysis

### Network Activity
- **No external API calls detected**
- **No data exfiltration**
- **No remote code loading**
- Homepage URL (add0n.com) is only opened on install/update for FAQ purposes

### Cookie Access
- Extension has `cookies` permission for YouTube domain only
- Cookie manipulation is limited to the PREF cookie for legitimate theme control
- No cookie harvesting or unauthorized access to sensitive cookies

### Permissions Review
- `storage`: Used for user preferences (colors, schedule settings)
- `cookies`: Required to modify YouTube's PREF cookie for theme switching
- `alarms`: Used for scheduled theme switching feature
- `idle`: Used to detect when user is active for scheduled theme changes
- `*://*.youtube.com/*`: Necessary for content script injection and cookie access

All permissions are justified and properly scoped to the extension's stated functionality.

## Privacy Analysis

### Data Collection
- No data collection mechanisms detected
- No analytics or tracking code
- All preferences stored locally using chrome.storage.local
- No telemetry or user behavior monitoring

### Third-Party Services
- No third-party scripts or libraries
- No external API dependencies
- Homepage link to add0n.com is passive (not loaded in background)

## False Positives Analysis

### Cookie Manipulation
While the extension modifies cookies, this is the intended and legitimate functionality. The PREF cookie manipulation is:
- Limited to YouTube domain only
- Uses YouTube's official dark mode mechanism
- Transparent and documented in code comments
- Essential for the extension's stated purpose

### Homepage Opening
The extension opens its homepage on install/update, which could be flagged as unwanted behavior, but:
- This is standard practice for extension FAQ/changelog
- Only occurs during install or significant updates (45+ days apart)
- User can disable this via the `faqs` preference
- Not an active indicator (requires user installation action)

## API Endpoints Analysis

| Endpoint | Purpose | Data Sent | Risk |
|----------|---------|-----------|------|
| None | N/A | N/A | N/A |

No external API endpoints are contacted by this extension.

## Code Quality

- Clean, readable code with comments
- No obfuscation or minification
- Standard Chrome Extension API usage
- Proper error handling
- MV3 compliant implementation

## Overall Risk Assessment

**RISK LEVEL: CLEAN**

**Justification**: This extension is a straightforward, legitimate dark theme implementation that uses YouTube's native dark mode mechanism. It introduces no security vulnerabilities, collects no data, makes no external network requests, and all permissions are properly justified. The code is transparent and follows best practices. There are no privacy concerns or malicious behaviors present.

**Recommendation**: Safe for use. The extension delivers exactly what it promises with no hidden functionality.
