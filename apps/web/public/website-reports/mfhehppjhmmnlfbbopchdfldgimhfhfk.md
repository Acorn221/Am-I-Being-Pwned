# Vulnerability Report: Google Classroom

## Metadata
| Field | Value |
|-------|-------|
| Extension Name | Google Classroom |
| Extension ID | mfhehppjhmmnlfbbopchdfldgimhfhfk |
| Version | 1.8 |
| Manifest Version | 2 |
| Approximate Users | 20,000,000 |
| Publisher | Google |

## Executive Summary

Google Classroom is a **web app launcher** -- not a traditional browser extension. It contains **zero executable code**. The entire extension consists of a manifest.json, a single icon (icon_128.png), and localization files (_locales/). Its sole function is to provide a shortcut that opens `https://classroom.google.com/` in the browser.

There are **no background scripts, no content scripts, no popup pages, no injected JavaScript, no service workers, and no permissions beyond the implicit launch URL**. This is one of the most minimal Chrome Web Store entries possible.

## Manifest Analysis

```json
{
  "update_url": "https://clients2.google.com/service/update2/crx",
  "name": "__MSG_appName__",
  "short_name": "Classroom",
  "description": "__MSG_appDesc__",
  "version": "1.8",
  "default_locale": "en",
  "app": {
    "urls": ["*://classroom.google.com/"],
    "launch": {
      "web_url": "https://classroom.google.com/"
    }
  },
  "icons": {
    "128": "icon_128.png"
  },
  "manifest_version": 2
}
```

### Permissions
- **None declared.** No `permissions`, `optional_permissions`, `host_permissions`, or `content_scripts` fields exist.

### Content Security Policy
- **Not specified** (not needed -- there is no executable content).

### App Type
- This is a legacy **hosted app** (`"app"` key with `"launch"` > `"web_url"`). It simply opens a URL. It does not have access to any Chrome extension APIs.

## Vulnerability Details

**No vulnerabilities found.**

There is literally no code to analyze. The extension contains:
1. `manifest.json` -- app launcher configuration
2. `icon_128.png` -- app icon
3. `_locales/*/messages.json` -- localized name/description strings (43 locales)
4. `_metadata/verified_contents.json` -- Chrome Web Store integrity verification

No JavaScript, HTML, CSS, WASM, or any other executable files exist in this extension.

## False Positive Table

| Pattern | File | Verdict |
|---------|------|---------|
| N/A | N/A | No code to trigger any false positives |

## API Endpoints Table

| Endpoint | Purpose | Risk |
|----------|---------|------|
| `https://classroom.google.com/` | Launch URL (opens in browser) | None -- standard navigation |
| `https://clients2.google.com/service/update2/crx` | Chrome Web Store auto-update | None -- standard CWS mechanism |

## Data Flow Summary

There is no data flow. The extension performs no data collection, no network requests, and no DOM manipulation. It is a static launcher that opens a URL when the user clicks it.

## Overall Risk: **CLEAN**

This is a Google-published web app launcher with zero executable code, zero permissions, and zero attack surface. It simply provides a Chrome app shelf shortcut to `classroom.google.com`. There is nothing to exploit.
