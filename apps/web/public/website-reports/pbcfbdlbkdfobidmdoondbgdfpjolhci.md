# Vulnerability Report: WebP / Avif image converter

## Extension Metadata
- **Extension ID**: pbcfbdlbkdfobidmdoondbgdfpjolhci
- **Extension Name**: WebP / Avif image converter
- **Version**: 1.3.1
- **User Count**: ~100,000
- **Manifest Version**: 3
- **Analysis Date**: 2026-02-07

## Executive Summary

The WebP / Avif image converter extension is a legitimate image conversion utility that allows users to convert images between various formats (WebP, AVIF, PNG, JPG, BMP, GIF, ICO) through a context menu interface. The extension operates entirely client-side using browser Canvas APIs for image conversion and does not communicate with external servers. After comprehensive analysis, **no malicious behavior, data exfiltration, or security vulnerabilities were identified**.

The extension demonstrates good security practices: minimal permissions for its functionality, local-only processing, no remote code execution, and no tracking/analytics. All network requests are limited to fetching user-selected images for conversion purposes.

## Vulnerability Details

### No Vulnerabilities Found

After thorough analysis of the extension's codebase, **no security vulnerabilities, malicious behavior, or privacy concerns were identified**.

## False Positive Analysis

| Pattern | Location | Verdict | Explanation |
|---------|----------|---------|-------------|
| `fetch()` calls | `background/imageconverter.js:65, 245` | **CLEAN** | Only used to fetch user-selected images for conversion. URL comes from context menu click on image (info.srcUrl). No external API calls. |
| `XMLHttpRequest` | `background/imageconverter.js:213-223` | **CLEAN** | Only used for local file:// URL access in Chromium browsers when user has granted file scheme permission. Legitimate functionality. |
| Broad host permissions `*://*/*` | `manifest.json:36-38` | **CLEAN** | Required to fetch images from any domain when user right-clicks and selects "Convert and save image as". Cannot be scoped more narrowly for this use case. |
| `chrome.downloads` permission | `manifest.json:33` | **CLEAN** | Essential for the extension's core functionality of saving converted images. |
| Dynamic code in `tabs.executeScript` | `background/imageconverter.js:164` | **CLEAN** | Firefox-only code to navigate duplicated tab to local file URL. Uses template literal with user's selected image URL - no eval or Function(). |
| Storage access | `background/storage.js` | **CLEAN** | Only stores user preferences (conversion settings, quality, download paths). No PII collection. |

## API Endpoints

**No external API endpoints detected.**

The extension operates entirely offline and does not make any network requests to remote servers. All `fetch()` calls are limited to:
- User-selected image URLs (from context menu)
- Local file:// URLs (when user has granted permission)

## Data Flow Summary

### Permissions Analysis
```json
{
  "permissions": ["storage", "downloads", "contextMenus"],
  "host_permissions": ["*://*/*"]
}
```

- **storage**: Stores user preferences (conversion format, quality settings, download paths)
- **downloads**: Saves converted images to disk
- **contextMenus**: Adds "Convert and save image as" option to image context menu
- **host_permissions**: Required to fetch any image the user right-clicks on

**No Content Security Policy** is defined, but this is acceptable for MV3 extensions with no web-accessible resources.

### Data Flow
1. **User Interaction**: User right-clicks on an image and selects "Convert and save image as" from context menu
2. **Image Fetching**: Extension fetches the image blob from the source URL (background/imageconverter.js:245)
   - For remote images: Uses `fetch(url, {headers: {...}})` with optional Accept headers for WebP/AVIF negotiation
   - For local files: Uses `XMLHttpRequest` (Chrome) or message passing (Firefox)
3. **Image Detection**: Analyzes image headers to detect format (AVIF, ICO, BMP, JPG, PNG, WebP, GIF, SVG)
4. **Conversion**: If conversion is enabled, uses Canvas API (`OffscreenCanvas` or `<canvas>`) to convert format
   - `convertStaticImage()` creates canvas, draws image, exports as new format with quality settings
5. **Download**: Saves converted image using `chrome.downloads.download()` API
   - Supports custom download paths and filenames with variable substitution
   - No data leaves the browser

**No data exfiltration, tracking, or analytics detected.**

### Background Scripts
- **service_worker.js**: Loads all background scripts via `importScripts()`
- **background/background.js**: Message handler, storage initialization, context menu creation
- **background/imageconverter.js**: Core conversion logic (fetch, detect format, convert, download)
- **background/storage.js**: User preferences storage (chrome.storage.local or chrome.storage.sync)
- **background/setup.js**: Default settings and validation filters

### Content Scripts
**None.** The extension does not inject any content scripts into web pages.

### Options Page
- **options/options.html**: Configuration UI for conversion settings
- **options/js/options.js**: Manages user preferences, validation, GUI updates
- All processing is local, no remote configuration

### Network Behavior
- **Outbound**: Only fetches user-selected images (necessary for conversion)
- **Inbound**: None
- **Third-party**: None
- **Analytics/Tracking**: None

## Security Strengths

1. **No External Dependencies**: No third-party libraries, SDKs, or analytics
2. **Local Processing**: All image conversion happens client-side using Canvas API
3. **No Remote Code**: No `eval()`, `Function()`, or remote script loading
4. **Minimal Permissions**: Only requests permissions necessary for functionality
5. **No PII Collection**: Does not access cookies, credentials, form data, or browsing history
6. **Open Source Behavior**: Clean, readable code with clear functionality
7. **No Obfuscation**: Code is well-structured and human-readable after jsbeautifier

## Overall Risk Assessment

**Risk Level: CLEAN**

This extension is a legitimate, well-designed image conversion utility with no malicious behavior. It exemplifies good extension development practices:
- Minimal permission model
- Client-side only processing
- No tracking or data collection
- Clear, maintainable code
- Transparent functionality matching description

The extension is safe for users and poses no security or privacy risks.

## Recommendations

**For Users**: This extension is safe to use. No security concerns identified.

**For Developers**: No changes needed. The extension follows security best practices.

## Conclusion

The WebP / Avif image converter extension is a clean, well-implemented utility extension that performs exactly as advertised. It converts images between formats using browser Canvas APIs without any external network communication (except fetching the user-selected images). No vulnerabilities, malware, or privacy concerns were identified during this analysis.
