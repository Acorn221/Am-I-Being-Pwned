# Vulnerability Report: Search and Replace

## Metadata
- **Extension ID**: bldchfkhmnkoimaciljpilanilmbnofo
- **Extension Name**: Search and Replace
- **Version**: 2.0.9
- **Manifest Version**: 3
- **Analysis Date**: 2026-02-15

## Executive Summary

"Search and Replace" is a browser utility that allows users to find and replace text on web pages. The extension operates entirely client-side with no external network communication. It uses content scripts to perform DOM manipulation and stores user preferences and search history in local/sync storage. All network-like activity is limited to loading local translation files from the extension's own `_locales` directory.

The extension's functionality is straightforward and transparent, with no data exfiltration, tracking, or privacy concerns. The static analyzer flagged potential exfiltration flows involving chrome.storage → fetch, but these are false positives as the fetch calls only access bundled translation files via chrome.runtime.getURL().

## False Positives Analysis

### Static Analyzer Findings
The ext-analyzer reported three HIGH-severity exfiltration flows:
1. `chrome.storage.local.get → fetch` in background.js
2. `chrome.storage.sync.get → fetch` in background.js
3. `document.getElementById → fetch` in popup.js → background.js

**Reality**: All `fetch()` calls in the extension access only local extension resources:
- **background.js lines 413, 424**: Fetch translation files from `chrome.runtime.getURL("_locales/list.json")` and `chrome.runtime.getURL("_locales/{lang}/messages.json")`
- These are bundled files within the extension package, not external URLs
- No user data is ever transmitted over the network

The analyzer's "ATTACK SURFACE" findings regarding `innerHTML` assignments are also not exploitable because:
- Messages come from internal extension components only
- No external input reaches these sinks
- The extension doesn't use `externally_connectable` or accept messages from web pages

## Functionality Analysis

### Core Features
1. **Text Search/Replace**: Performs regex-based find-and-replace operations on page DOM
2. **Options**: Match case, whole word, input fields only, hidden content, regex mode, HTML replacement
3. **History**: Saves recent search/replace operations to chrome.storage.local
4. **Saved Instances**: Can save URL-specific replacements that auto-apply on page load
5. **i18n Support**: Loads translations from bundled locale files

### Storage Usage
- **chrome.storage.local**: User search history, saved instances, preferences
- **chrome.storage.sync**: Preferred language setting
- No data leaves the browser

### Permissions Justification
- **activeTab**: Required to inject content scripts and perform replacements
- **storage**: Required to persist user history and preferences
- **notifications**: Shows install notification
- **host_permissions (http/https)**: Required for content scripts to run on all pages (user chooses when to activate)

## API Endpoints Analysis
| Endpoint | Purpose | Data Sent | Risk |
|----------|---------|-----------|------|
| _locales/list.json | Load available languages | None | None (local file) |
| _locales/{lang}/messages.json | Load translations | None | None (local file) |

## Overall Risk Assessment
**RISK LEVEL: CLEAN**

**Justification**: This extension performs its advertised function (search and replace on web pages) with no hidden functionality, no data collection, no external network communication, and no privacy violations. The code is well-structured TypeScript compiled to JavaScript with standard webpack bundling (not obfuscation). All storage is local and used only for legitimate user preferences. The extension is a pure client-side utility tool.
