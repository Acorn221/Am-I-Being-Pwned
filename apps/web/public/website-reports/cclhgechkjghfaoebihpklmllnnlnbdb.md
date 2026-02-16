# Vulnerability Report: Paint Online - Drawing Tool

## Metadata
- **Extension ID**: cclhgechkjghfaoebihpklmllnnlnbdb
- **Extension Name**: Paint Online - Drawing Tool
- **Version**: 2.0
- **Users**: ~50,000
- **Manifest Version**: 3
- **Analysis Date**: 2026-02-15

## Executive Summary

Paint Online - Drawing Tool is a legitimate browser extension that provides drawing and annotation functionality directly on web pages. The extension allows users to create drawings, annotations, and sketches on any webpage using various drawing tools (pencil, text, shapes, color picker) and capture screenshots of their work.

After comprehensive analysis of the codebase, including static analysis and manual code review, no security or privacy concerns were identified. The extension operates entirely client-side, stores data locally in localStorage and chrome.storage, and does not communicate with any external servers or collect user data. All functionality aligns with the extension's stated purpose.

## Vulnerability Details

No vulnerabilities were identified during the analysis.

## False Positives Analysis

### 1. Static Analyzer EXFILTRATION Flag
**Static Analysis Finding**: The static analyzer flagged one "exfiltration" flow: `chrome.tabs.query → *.src`

**Analysis**: This is a false positive. The flagged code appears in the service worker (worker.js) where `chrome.tabs.query` is used to get the current active tab, followed by setting an image source (`i.src = n`) within the `getPixelColor` function. This operation:
- Queries the current tab to capture a screenshot via `chrome.tabs.captureVisibleTab`
- Creates a canvas element and draws the captured image to extract pixel color data
- Sets the image source to the screenshot data URL for color picker functionality
- Does NOT send data to any external server
- Is a legitimate client-side canvas operation for the eyedropper/color picker tool

### 2. Host Permissions `*://*/*`
**Permission**: The extension requests `*://*/*` host permissions

**Analysis**: This broad permission is necessary and appropriate for this extension type because:
- The drawing tool needs to inject canvas overlays on any webpage the user visits
- Users expect to draw on any website they choose
- The extension uses `chrome.scripting.executeScript` to inject the drawing panel on user-activated tabs
- No data from these pages is collected or transmitted
- The permission is used solely for injecting the drawing UI

### 3. localStorage Usage
**Pattern**: The extension stores canvas snapshots in localStorage

**Analysis**: This is legitimate functionality:
- Stores drawing snapshots keyed by URL path (`WP_CRX_STORAGE_SNAPSHOT_` + pathname)
- Allows users to preserve their drawings when revisiting the same page
- Data never leaves the browser
- Implements size limits and error handling for quota issues
- Completely client-side persistence

## API Endpoints Analysis

| Endpoint | Purpose | Data Sent | Risk |
|----------|---------|-----------|------|
| N/A | No external endpoints contacted | N/A | CLEAN |

## Code Behavior Analysis

### Service Worker (worker.js)
- Handles extension icon clicks to inject drawing scripts
- Manages screenshot capture functionality
- Stores/retrieves user configuration in chrome.storage.local
- Implements message passing between background and content scripts
- No network requests or external communications

### Drawing Panel (embed-panel.js)
- Implements canvas-based drawing functionality
- Provides text cursor, drawing tools (pen, eraser, shapes, etc.)
- Manages drawing history with undo/redo
- Stores canvas state in localStorage for persistence
- Handles mouse/touch events for drawing interactions
- No external dependencies or network calls

### Preview (preview.js)
- Displays screenshot preview in a new tab
- Allows cropping and downloading of screenshots
- Implements print functionality
- All operations are client-side canvas manipulations
- Downloads use data URLs, no server uploads

### Core Functionality
1. **Drawing Tools**: Pencil, text, shapes, color picker, eraser, fill bucket
2. **Screenshot Capture**: Uses `chrome.tabs.captureVisibleTab` API
3. **Local Persistence**: Saves drawings to localStorage per-URL
4. **Configuration**: Stores user preferences (tool selection, colors, thickness) in chrome.storage

## Overall Risk Assessment

**RISK LEVEL: CLEAN**

**Justification**:

This extension is a straightforward, legitimate drawing tool with no security or privacy concerns. Key findings supporting this assessment:

1. **No Data Exfiltration**: The extension makes zero external network requests. All data remains client-side in localStorage and chrome.storage.

2. **Appropriate Permissions**: While the extension requests broad host permissions (`*://*/*`), this is necessary and properly used for its stated functionality of allowing users to draw on any webpage.

3. **Transparent Functionality**: All code behavior aligns with the extension's description as a drawing and screenshot tool.

4. **No Obfuscation**: The code is clean, well-structured JavaScript with standard drawing and canvas operations. The static analyzer's "obfuscated" flag appears to be triggered by code minification, not intentional obfuscation.

5. **Safe APIs**: Uses standard Chrome extension APIs appropriately:
   - `chrome.tabs.captureVisibleTab` for screenshots
   - `chrome.scripting.executeScript` for injecting drawing UI
   - `chrome.storage.local` for configuration
   - Canvas API for drawing operations

6. **No Malicious Patterns**: No keylogging, no cookie harvesting, no hidden tracking, no ad injection, no credential theft, no suspicious eval usage.

The extension provides exactly the functionality it advertises with no hidden behavior or privacy concerns.
