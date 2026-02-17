# Vulnerability Report: PDF Viewer

## Metadata
- **Extension ID**: jdlkkmamiaikhfampledjnhhkbeifokk
- **Extension Name**: PDF Viewer
- **Version**: 1.0.11
- **Users**: ~200,000
- **Manifest Version**: 3
- **Analysis Date**: 2026-02-15

## Executive Summary

PDF Viewer is a Chrome extension that provides an in-browser PDF viewing experience using the Mozilla PDF.js library. The extension intercepts PDF downloads and navigation events to redirect them to an embedded PDF.js viewer with customizable rendering options.

After thorough analysis including static code analysis and manual code review, this extension exhibits no malicious behavior or privacy concerns. The ext-analyzer flagged two "exfiltration" flows involving fetch() calls, but these are false positives - the fetch is used solely to retrieve the favicon of the PDF's hosting domain for display purposes. All functionality aligns with the extension's stated purpose of providing a PDF viewing interface.

## False Positives Analysis

### Fetch Calls Flagged by ext-analyzer

The static analyzer reported two "HIGH" severity exfiltration flows involving `chrome.storage.local.get → fetch` and `document.getElementById → fetch`. Manual code review reveals these are both the same benign operation in `bg/main/replace.js`:

**Code (lines 57-71)**:
```javascript
try {
  const e = params.get("file").split("#")[0],
    t = (e = "chrome://favicon/" + e) => {
      const t = document.querySelector('link[rel*="icon"]') || document.createElement("link");
      t.type = "image/x-icon", t.rel = "shortcut icon", t.href = e, document.head.appendChild(t)
    },
    {
      hst: n,
      prt: o
    } = new URL(e);
  if (o.startsWith("http")) {
    const e = o + "//" + n + "/favicon.ico";
    fetch(e).then((n => t(n.ok ? e : void 0)), t()).catch((() => {}))
  }
} catch (e) {}
```

**Analysis**: This code attempts to fetch the favicon from the domain hosting the PDF file being viewed. The fetched favicon is then displayed in the browser tab to provide visual context about the PDF's source. No user data is transmitted - only an outbound GET request for a favicon.ico file. This is a standard UI enhancement feature.

### WASM and Obfuscation Flags

The analyzer flagged WASM and obfuscation. The WASM is part of the legitimate PDF.js library used for PDF rendering. The "obfuscation" flag appears to be triggered by variable name shortening (e.g., `hst`, `prt`, `lnk`) which is common in bundled/minified code, not actual malicious obfuscation.

## Functionality Analysis

### Core Features

1. **PDF Interception**: Uses `webRequest.onHeadersReceived` to detect PDF files based on Content-Type headers and redirects to internal viewer
2. **File Protocol Support**: Registers handlers for `file://` URLs ending in `.pdf`
3. **Context Menu Integration**: Provides "Open with PDF Viewer" options for PDF links
4. **Customizable Viewer**: Offers theme selection (dark/light) and PDF.js rendering options via extension popup
5. **Link Copying**: Allows users to copy the current PDF URL to clipboard

### Permission Usage

All permissions are justified:
- `webRequest` + `webNavigation`: Required to intercept PDF navigation events
- `host_permissions` (https://*/, http://*/): Necessary to intercept PDFs from any domain
- `storage`: Stores user preferences (theme, rendering options)
- `contextMenus`: Provides right-click menu options

### Network Activity

The only network requests made by the extension are:
1. Favicon fetches from PDF hosting domains (as described above)
2. No analytics, telemetry, or external API calls detected
3. No user data exfiltration

## Overall Risk Assessment

**RISK LEVEL: CLEAN**

**Justification**: This extension performs exactly as advertised - it provides a PDF viewing interface using the open-source PDF.js library. No malicious behavior, privacy violations, or security vulnerabilities were identified. The fetch() calls flagged by static analysis are benign favicon retrievals for UI purposes. The extension does not collect, transmit, or mishandle user data. All permissions are appropriately scoped to the extension's stated functionality.
