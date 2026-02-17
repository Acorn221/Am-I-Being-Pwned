# Vulnerability Report: PDF Editor for Chrome:Edit, Fill, Sign, Print

## Metadata
- **Extension ID**: gphandlahdpffmccakmbngmbjnjiiahp
- **Extension Name**: PDF Editor for Chrome:Edit, Fill, Sign, Print
- **Version**: 0.5.5
- **Users**: ~200,000
- **Manifest Version**: 3
- **Analysis Date**: 2026-02-15

## Executive Summary

This extension claims to be a PDF viewer/editor but exhibits concerning data collection practices. While it is built on the legitimate Mozilla PDF.js library, it has been modified to send PDF file URLs, file contents, and Gmail metadata to pdffiller.com servers without adequate disclosure. The extension intercepts all PDF files across all websites, converts web pages to PDFs, and uploads this data along with email sender/subject information when processing Gmail attachments. Although this appears to be the intended functionality of a PDF editing service, the broad scope of data collection (including local file access, Gmail scraping, and webpage conversion) combined with very broad permissions represents a significant privacy risk.

The extension's poor user rating (2.3/5) suggests user dissatisfaction, potentially related to these privacy practices or other functionality issues.

## Vulnerability Details

### 1. HIGH: Undisclosed PDF and Web Content Exfiltration to Third-Party Server

**Severity**: HIGH
**Files**: js/background.js, js/config.js, js/inject.js
**CWE**: CWE-359 (Exposure of Private Personal Information to an Unauthorized Actor)

**Description**: The extension sends PDF URLs, full PDF file contents (base64-encoded), webpage URLs, and filenames to pdffiller.com servers for all PDF interactions and webpage conversions. This occurs across all websites due to the `<all_urls>` content script injection.

**Evidence**:
```javascript
// js/config.js
var config = {
    api_url: 'https://www.pdffiller.com/flash/data/up.php',
    converter_server_url: 'http://mozilla-apps.pdffiller.com/api/pdf_converter'
};

// js/background.js - Sending PDF URLs
function sendToPdffiller(url, filename, viewer) {
    $.post(config.api_url, {
        source: 1,
        filename: filename,
        pdf_url: url,  // URL of PDF sent to remote server
        type: 'chrome.ext',
        out: 'json'
    }, ...);
}

// js/background.js - Sending full file contents
if ('file' in request) {
    delete options.pdf_url;
    options.pdf_file = request.file;  // Base64-encoded file content
}

// js/background.js - Converting web pages to PDF
function convert(url, width, height, attemptsLeft) {
    const body = new FormData()
    body.append('url', url);  // Current webpage URL sent to converter
    fetch(config.converter_server_url, {method: 'post', body})
}
```

**Verdict**: While PDF editing services legitimately need to receive PDF files, the extension does not adequately disclose the scope of data transmission. Users may not realize that PDFs from any source (including private documents from local files, intranet sites, or authenticated web services) are being sent to third-party servers.

### 2. HIGH: Gmail Metadata Collection and Transmission

**Severity**: HIGH
**Files**: js/inject.js, js/background.js
**CWE**: CWE-359 (Exposure of Private Personal Information to an Unauthorized Actor)

**Description**: The extension specifically targets Gmail, scraping email sender addresses and subject lines from the DOM and sending them to pdffiller.com along with PDF attachments.

**Evidence**:
```javascript
// js/inject.js - Gmail DOM scraping
function getFile(url, filename, type = 'CHROME.EXT') {
    ...
    case 'GMAIL':
        var from = $('.iv .gD').attr('email');      // Extract sender email
        var subject = $('.nH .ha .hP').html();      // Extract subject line
        sendToPdffillerGmailApi(file, filename, from, subject);
        break;
}

// js/background.js - Sending Gmail metadata to server
function sendPdffillerGmailAPI(request, sender, sendResponse) {
    $.post(config.api_url, {
        filename: request.filename,
        pdf_file: request.file,
        type: 'GMAIL',
        from: request.from,        // Email sender address
        subject: request.subject,  // Email subject line
        out: 'json'
    }, ...);
}
```

**Verdict**: Collecting and transmitting email metadata (sender addresses and subject lines) represents a significant privacy intrusion. Users processing PDF attachments from sensitive emails (legal, medical, financial) would have this contextual information sent to pdffiller.com servers.

### 3. MEDIUM: Insecure HTTP Endpoint for PDF Conversion

**Severity**: MEDIUM
**Files**: js/config.js
**CWE**: CWE-319 (Cleartext Transmission of Sensitive Information)

**Description**: The PDF converter endpoint uses HTTP instead of HTTPS, transmitting webpage URLs and conversion requests in cleartext.

**Evidence**:
```javascript
// js/config.js
converter_server_url: 'http://mozilla-apps.pdffiller.com/api/pdf_converter'  // HTTP, not HTTPS
```

**Verdict**: While the main API endpoint uses HTTPS, the converter service uses HTTP, creating a man-in-the-middle vulnerability where attackers could intercept webpage URLs being converted to PDF.

### 4. MEDIUM: Overly Broad Permissions and Content Script Injection

**Severity**: MEDIUM
**Files**: manifest.json
**CWE**: CWE-250 (Execution with Unnecessary Privileges)

**Description**: The extension requests `<all_urls>` host permissions and injects content scripts on all websites at `document_start`, which is more permissive than necessary for a PDF viewer.

**Evidence**:
```json
"content_scripts": [{
    "matches": ["http://*/*", "https://*/*", "ftp://*/*", "file://*/*"],
    "run_at": "document_start",
    "all_frames": true,
    "js": ["contentscript.js", "libs/jquery.min.js", ...]
}],
"host_permissions": ["*://*/*"]
```

**Verdict**: While PDF viewing does require intercepting PDF files across sites, the `document_start` timing and injection on all frames is excessive. This creates a large attack surface and enables the Gmail scraping functionality.

### 5. LOW: Local File Access

**Severity**: LOW
**Files**: js/background.js, manifest.json
**CWE**: CWE-552 (Files or Directories Accessible to External Parties)

**Description**: The extension can access local files (`file:///`) and uploads their contents to pdffiller.com servers.

**Evidence**:
```javascript
// js/background.js
async function getLocalDocumentByUrl(request) {
    const {url} = request;
    const idxThree = url.indexOf('file://');
    const isLocalDoc = (idxThree > -1);

    if (!isLocalDoc) return;

    const response = await fetch(url);  // Access local file
    const buffer = await response.arrayBuffer();
    request.file = btoa(...);  // Convert to base64 for upload
}
```

**Verdict**: Users who open local PDF files may not realize these private documents are being uploaded to external servers. However, this is somewhat expected behavior for a cloud PDF editing service.

## False Positives Analysis

1. **PDF.js Library Code**: The extension is built on Mozilla's legitimate PDF.js library (viewer.js, pdf.js, pdf.worker.js). The majority of the codebase is standard PDF rendering functionality, which is not malicious.

2. **Telemetry Code (Commented Out)**: The `telemetry.js` file contains commented-out Mozilla telemetry code that would send browser version statistics to `pdfjs.robwu.nl`. This code is disabled and includes a check to only run on the official Mozilla PDF.js extension ID (`oemmndcbldboiebfnladdacbdfmadadm`), so it would never execute in this fork.

3. **webRequest API Usage**: The extension uses `chrome.webRequest` to intercept PDF files and redirect them to the viewer, which is legitimate functionality for a PDF viewer extension.

## API Endpoints Analysis

| Endpoint | Purpose | Data Sent | Risk |
|----------|---------|-----------|------|
| https://www.pdffiller.com/flash/data/up.php | Main API for PDF upload | PDF URLs, PDF files (base64), filenames, source identifier | HIGH - Receives all PDF content |
| https://www.pdffiller.com/flash/data/up.php (Gmail) | Gmail PDF processing | PDF files, filenames, email sender addresses, email subjects | HIGH - Receives sensitive email metadata |
| http://mozilla-apps.pdffiller.com/api/pdf_converter | Webpage to PDF conversion | Webpage URLs, viewport dimensions | MEDIUM - Insecure HTTP transmission |

## Overall Risk Assessment

**RISK LEVEL: HIGH**

**Justification**: While this extension appears to implement its stated functionality (PDF editing via pdffiller.com), it collects and transmits significant amounts of user data without adequate disclosure:

1. **Privacy Risk**: All PDF interactions (URLs and full file contents) from any source are sent to pdffiller.com, including potentially sensitive documents from local files, corporate intranets, or authenticated web services.

2. **Gmail Metadata Scraping**: The extension specifically targets Gmail to extract and transmit email sender addresses and subject lines, which could reveal sensitive information about the user's communications.

3. **Disclosure Gap**: The extension description mentions "Edit, e-sign, print or fax PDFs" but does not clearly state that all PDFs will be uploaded to pdffiller.com servers, or that Gmail metadata will be collected.

4. **Broad Attack Surface**: The `<all_urls>` content script injection at `document_start` on all frames creates a large attack surface and enables the Gmail scraping capability.

5. **User Dissatisfaction**: The 2.3/5 star rating with 200,000 users suggests widespread user dissatisfaction, potentially related to privacy concerns or unexpected behavior.

The extension is not malware in the traditional sense - it implements a legitimate PDF editing service. However, the scope of data collection, particularly Gmail metadata scraping, combined with inadequate disclosure to users, constitutes a HIGH privacy risk. Users expecting a simple PDF viewer may be surprised to find their documents and email metadata being transmitted to third-party servers.
