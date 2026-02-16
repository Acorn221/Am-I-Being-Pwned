# Vulnerability Report: Mes Envies : Ajoutez à votre liste de cadeaux

## Metadata
- **Extension ID**: polapjjgommcmlcbbplneckjgblmgfmk
- **Extension Name**: Mes Envies : Ajoutez à votre liste de cadeaux
- **Version**: 2.3
- **Users**: Unknown
- **Manifest Version**: 3
- **Analysis Date**: 2026-02-15

## Executive Summary

"Mes Envies" is a French wishlist extension that allows users to save products from any website to their gift registry on MesEnvies.fr. The extension extracts product information (title, description, price, images) from web pages and sends it to the MesEnvies.fr service. The extension is functionally legitimate and operates transparently within its stated purpose.

While the extension requests broad permissions (`<all_urls>` in both content scripts and host permissions), this is necessary for its core functionality of parsing product information from any e-commerce site. The extension does collect page data, but only when the user actively clicks to add an item to their wishlist, and the data is sent to a clearly disclosed endpoint (mesenvies.fr).

## Vulnerability Details

### 1. LOW: Broad Content Script Injection on All URLs

**Severity**: LOW
**Files**: manifest.json, content.js, js/controllers/mdpageparser.js, js/models/item.js
**CWE**: CWE-250 (Execution with Unnecessary Privileges)
**Description**: The extension injects content scripts on `<all_urls>` to enable product extraction from any website. While necessary for the extension's functionality, this provides a large attack surface if the extension were compromised or contained XSS vulnerabilities.

**Evidence**:
```json
"content_scripts": [{
  "matches": ["<all_urls>"],
  "js": [
    "js/models/item.js",
    "js/controllers/mdpageparser.js",
    "content.js"
  ],
  "run_at": "document_end"
}]
```

The content script listens for messages and can extract the entire page DOM:
```javascript
chrome.runtime.onMessage.addListener(function (msg, sender, sendResponse) {
    if (msg.text === 'get_gift_item') {
        var browser=new MDSmallBrowser();
        var pageParser=new MSPageParser();
        var item=new MDGiftItem();
        pageParser.parseCurrentDocument(browser, item, function(itemObject) {
           sendResponse(item);
        });
    } else if (msg.text==='get_document') {
        sendResponse(document.all[0].outerHTML);
    }
});
```

**Verdict**: This is standard behavior for product/wishlist extensions. The data extraction only occurs when the user actively clicks the extension popup to add an item. The extension does not exfiltrate data passively or in the background. This is expected functionality, not malicious behavior.

## False Positives Analysis

1. **All URLs Content Script**: While ext-analyzer flagged this as potentially suspicious, it is required for the extension to parse product information from any e-commerce website the user visits. The extension only extracts data when the user explicitly clicks to add an item.

2. **Full DOM Access**: The `get_document` message handler returns `document.all[0].outerHTML`, which provides the entire page HTML. This is used for parsing product metadata and is only triggered by user action through the popup interface.

3. **Obfuscated Code**: The static analyzer detected obfuscated code, but examination of the deobfuscated source shows this is standard webpack bundling, not intentional obfuscation. The code is readable and straightforward.

## API Endpoints Analysis

| Endpoint | Purpose | Data Sent | Risk |
|----------|---------|-----------|------|
| https://www.mesenvies.fr/liste-naissance | Main API endpoint | Product URL, title, description, price, image, user credentials (when logged in) | LOW - Legitimate service endpoint |
| https://ajax.googleapis.com/ | External resource loading | None (host permission only) | NONE |
| https://fonts.googleapis.com | Google Fonts | None (loaded in popup HTML) | NONE |

The extension sends three types of requests to the MesEnvies API:
1. **Query Item** (r=1100): Checks if a product URL is already in the user's wishlist
2. **Add Item** (r=1101): Adds a new product to the wishlist
3. **Authorize User** (r=1102): Authenticates user credentials

All API calls use POST with JSON payloads:
```javascript
MDApiController.prototype.performApiCall=async function(url, dataObject, callback, errorCallback) {
    var params = "data="+encodeURIComponent(JSON.stringify(dataObject));
    await fetch(url, {
        method: "POST",
        cache: "no-cache",
        headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
        body: params
    })
    .then((response) => response.json())
    .then((data) => { callback(data) })
    .catch((reason) => { errorCallback('Network error.'); });
}
```

## Overall Risk Assessment

**RISK LEVEL: LOW**

**Justification**:
The extension operates transparently within its stated purpose as a wishlist/gift registry tool. While it has broad permissions (`<all_urls>`), these are necessary and appropriately used for parsing product information from e-commerce sites. The extension:

- Only extracts data when the user explicitly clicks to add an item
- Sends data to a clearly disclosed service (MesEnvies.fr)
- Does not collect sensitive information beyond product details and user credentials
- Uses standard security practices (HTTPS, POST requests)
- Does not inject ads, modify page content, or exhibit malicious behavior

The main concern is the broad permission scope, but this is justified by the extension's functionality and poses minimal risk to users who understand the extension's purpose. The extension would benefit from clearer privacy disclosures about what data is collected and how it is used, but no active security vulnerabilities were identified.
