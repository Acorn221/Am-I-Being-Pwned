# Security Analysis: PDF-XChange (blgipgnbmnikbdecnjmgckmndlkebhid)

## Extension Metadata
- **Name**: PDF-XChange
- **Extension ID**: blgipgnbmnikbdecnjmgckmndlkebhid
- **Version**: 1.4.3
- **Manifest Version**: 3
- **Estimated Users**: ~1,000,000
- **Developer**: Tracker Software Products (Canada) Ltd.
- **Analysis Date**: 2026-02-14

## Executive Summary
PDF-XChange is a legitimate browser extension that serves as a bridge between Chrome/Edge and the PDF-XChange Editor desktop application. The extension provides two main features: (1) converting web pages to PDF via MHTML capture, and (2) opening PDF files in the native PDF-XChange Editor. Analysis revealed no malicious behavior, tracking mechanisms, or data exfiltration. The ext-analyzer flagged two "exfiltration flows" which are **FALSE POSITIVES** - these are legitimate operations where the extension downloads PDF files from the current tab URL to pass them to the native application via the `nativeMessaging` API.

**Overall Risk Assessment: CLEAN**

## Vulnerability Assessment

### 1. "Exfiltration Flows" from ext-analyzer (FALSE POSITIVES)
**Severity**: N/A (Not a Vulnerability)
**Files**: `/background.js` (lines 206-209, 379-428)

**ext-analyzer Report**:
```
EXFILTRATION (2 flows):
  [HIGH] chrome.tabs.query → fetch    background.js
  [HIGH] chrome.tabs.get → fetch      background.js
```

**Analysis**:
These are flagged as exfiltration flows because the extension:
1. Queries tab information (`chrome.tabs.query()` or `chrome.tabs.get()`)
2. Uses `fetch()` to download data

However, this is **legitimate functionality** for a PDF editor integration:

#### Flow 1: HTML-to-PDF Conversion (`doHTMLToPDF`)
**Code Evidence** (`background.js`, lines 202-272):
```javascript
async function doHTMLToPDF(message, sender, sendResponse) {
	// fetch active tab, based on the popup type
	let tab;
	if (POPUP_TYPE === POPUP_TYPE_IFRAME) {
		let tabs = await chrome.tabs.query({ currentWindow: true, active: true });
		if (tabs.length > 0) {
			tab = tabs[0];
		}
	} else if (POPUP_TYPE === POPUP_TYPE_POPUP) {
		if (message.tab_id) {
			tab = await chrome.tabs.get(message.tab_id);
		}
	}

	const tabID = tab.id;
	const tabTitle = tab.title;
	const tabURL = tab.url;

	chrome.pageCapture.saveAsMHTML({ tabId: tabID }, (mhtmlData) => {
		const reader = new FileReader();
		reader.addEventListener('loadend', (event) => {
			const mhtml = event.target.result.replace(new RegExp(regexp, 'm'), '');
			DataTransmitter.sendData(tabID, mhtml, tabTitle, tabURL, "MHTMLoPDF", 2.0);
		});
		reader.readAsText(mhtmlData);
	});
}
```

**Purpose**:
- User clicks "Convert to PDF" in the extension popup
- Extension gets active tab info to determine which page to convert
- Uses Chrome's `pageCapture.saveAsMHTML()` API (not fetch) to capture page content
- Sends MHTML data to native application via `nativeMessaging` for conversion
- **No external network request is made in this flow**

#### Flow 2: Open Remote PDF (`OnTabsOpenPDF`)
**Code Evidence** (`background.js`, lines 350-429):
```javascript
async function OnTabsOpenPDF(tabs)
{
	const tabID = tabs[0].id;
	const tabTitle = tabs[0].title;
	const tabURL = tabs[0].url;

	if (tabURL.startsWith('file:///')) {
		// handle local file
		sendNativeMessage(tabID, {
			"action": "openLocalPDF",
			"version": "1.0",
			"localPath": tabURL.replace(/^file:\/\/\//, '')
		});
	} else {
		// handle remote file. Download it first
		fetch(tabURL).then(async function (response) {
			const reader = response.body.getReader();
			const contentLength = +response.headers.get('Content-Length');

			let receivedLength = 0;
			let chunks = [];
			const progress = await ProgressesManager.getProgressForTab(tabID);
			while (true) {
				const { done, value } = await reader.read();
				if (done) {
					progress.setProgress('OpeningPDFDocument', -1, false);
					break;
				}
				chunks.push(value);
				receivedLength += value.length;
				let progressV = contentLength > 0 ? Math.round(receivedLength / contentLength * 100) : -1;
				progress.setProgress("DownloadingPDFDocument", progressV, true);
			}

			// Concatenate chunks into single Uint8Array
			let chunksAll = new Uint8Array(receivedLength);
			let position = 0;
			for (let chunk of chunks) {
				chunksAll.set(chunk, position);
				position += chunk.length;
			}
			const fileReader = new FileReader();
			fileReader.addEventListener('loadend', (loadEndEvent) => {
				DataTransmitter.sendData(tabID, loadEndEvent.target.result, tabTitle, tabURL, "openPDF", 3.0);
			});
			fileReader.readAsDataURL(new Blob([chunksAll.buffer]));
		}).catch(err => {
			console.error('PDF document dowloading has failed:', err);
			reportOperationFailure(tabID, { state: 1, message: 'PDF document dowloading has failed' });
		});
	}
};
```

**Purpose**:
- User visits a PDF URL in their browser and clicks "Open in PDF-XChange Editor"
- Extension uses `fetch(tabURL)` to download the PDF from its original location
- PDF data is converted to base64 (`readAsDataURL`)
- Data is sent to the **local native application** via `nativeMessaging`, NOT to an external server
- Native app (PDF-XChange Editor) opens the PDF for editing

**Data Flow**:
1. User-initiated action (clicks "Open in PDF-XChange Editor" button)
2. Extension fetches PDF from `tabURL` (the current page URL, e.g., `https://example.com/document.pdf`)
3. PDF binary data → base64 encoded
4. Sent to **localhost native messaging host** `com.trackersoftware.htmltopdf`
5. Native desktop application receives data and opens PDF

**Key Safety Indicators**:
- `fetch()` downloads from the **current tab URL only** (user is already viewing this PDF)
- Data destination is **native messaging host** (local desktop app), not an external server
- No user data collected beyond current tab URL and title
- Progress indicators shown to user during download
- Native messaging requires user to have PDF-XChange Editor installed locally
- Native host name: `com.trackersoftware.htmltopdf` (defined line 1)

**Verdict**: **NOT MALICIOUS** - This is legitimate PDF download-and-open functionality for a native application bridge.

---

### 2. Native Messaging Integration
**Severity**: N/A (Expected Behavior)
**Files**:
- `/background.js` (lines 1, 155-200, 282-346)

**Analysis**:
The extension uses Chrome's `nativeMessaging` API to communicate with the locally-installed PDF-XChange Editor desktop application.

**Code Evidence** (`background.js`):
```javascript
const NativeHostName = 'com.trackersoftware.htmltopdf';

function connect(tabID) {
	const port = chrome.runtime.connectNative(NativeHostName);
	NativeHostsPorts[tabID] = port;
	port.onMessage.addListener((function (tabID) {
		return function (message) {
			onNativeMessage(tabID, message);
		}
	})(tabID));
	port.onDisconnect.addListener((function (tabID) {
		return function () {
			const rt = chrome.runtime;
			const leMsg = rt.lastError.message;
			if (leMsg.includes("not found") || leMsg.includes("forbidden"))
				chrome.tabs.sendMessage(tabID, { content_op: "pdf-x-change.native_part_is_not_installed" });
			if (leMsg.includes("disabled by the system administrator"))
				chrome.tabs.sendMessage(tabID, {
					content_op: "pdf-x-change.native_part_is_not_permitted_by_admin",
					message: leMsg
				});
			ProgressesManager.stopProgressForTab(tabID);
			delete NativeHostsPorts[tabID];
		}
	})(tabID));
	return port;
}

function sendNativeMessage(tabID, message) {
	try {
		(NativeHostsPorts[tabID] || connect(tabID)).postMessage(message);
	} catch (err) {
		console.error(err);
		reportOperationFailure(tabID, { errorCode: 1024 });
	}
}
```

**Functionality**:
- Connects to native app via `chrome.runtime.connectNative()`
- Sends PDF/MHTML data to native app for processing
- Receives progress updates and completion status from native app
- Handles cases where native app is not installed or blocked by admin

**Data Transmitted to Native App**:
1. MHTML page captures (for HTML-to-PDF conversion)
2. PDF binary data (for opening remote PDFs)
3. Page titles and URLs (for file naming)
4. Action commands: `"MHTMLoPDF"`, `"openPDF"`, `"openLocalPDF"`, `"preferences"`, `"cancel"`

**Data Received from Native App**:
- Progress updates (`HTML2PDFProgress`)
- Completion status (`responseDone`)
- Error messages (`HTML2PDFError`)
- Chunking requests (`sendNextData`)

**Security Notes**:
- Native messaging requires a JSON manifest file installed in the OS that specifies which Chrome extension IDs are allowed to connect
- The native app runs with user permissions (not elevated)
- Communication is local-only (no network involved)
- Native host name follows standard reverse-DNS format

**Verdict**: **NOT MALICIOUS** - Standard Chrome native messaging implementation for desktop app integration.

---

### 3. Data Chunking for Large Files
**Severity**: N/A (Legitimate Functionality)
**Files**: `/background.js` (lines 281-347)

**Analysis**:
The extension implements a chunking mechanism to send large PDF/MHTML files to the native application in 1MB segments.

**Code Evidence** (`background.js`):
```javascript
const DataTransmitter = {
	chunkLength: 1048576, // 1 MB
	buffers: {},

	sendData: function (tabID, dataURL, tabTitle, tabURL, action, version)
	{
		const buffer = new TabBuffer(tabID, dataURL, tabTitle, tabURL, action, version);
		if (1 === buffer.sendData())
			this.buffers[tabID] = buffer;
	},

	sendNextChunk: function (tabID) {
		if (typeof this.buffers[tabID] !== 'undefined')
			if (0 === this.buffers[tabID].sendNextChunk())
				delete this.buffers[tabID]
	}
}

TabBuffer.prototype.sendNextChunk = function () {
	const chL = DataTransmitter.chunkLength;
	if (this.data.length - this.sentBytes > chL) {
		sendNativeMessage(this.tabID, {
			"action": this.action,
			"version": this.version,
			"data": this.data.substring(this.sentBytes, this.sentBytes + chL),
			"title": this.tabTitle,
			"url": this.tabURL,
			"dataRest": this.data.length - this.sentBytes - chL
		});
		this.sentBytes += chL;
		return 1;
	}
	else {
		sendNativeMessage(this.tabID, {
			"action": this.action,
			"version": this.version,
			"data": this.data.substring(this.sentBytes),
			"title": this.tabTitle,
			"url": this.tabURL,
			"dataRest": 0
		});
		this.data = "";
		this.sentBytes = 0;
		return 0;
	}
}
```

**Purpose**:
- Native messaging has size limits on messages
- Large PDFs and MHTML captures are split into 1MB chunks
- Native app requests next chunk via `"sendNextData"` action
- Prevents message size errors and provides better progress tracking

**Verdict**: **NOT MALICIOUS** - Standard technique for handling large data in native messaging.

---

### 4. Popup Iframe Injection (Optional UI Pattern)
**Severity**: N/A (Legitimate Functionality)
**Files**:
- `/content.js` (lines 1-100)
- `/background.js` (lines 5-7, 205, 623, 690-702, 869-891)

**Analysis**:
The extension offers two UI modes for its popup: standard browser action popup or an injected iframe.

**Code Evidence** (`background.js`):
```javascript
const POPUP_TYPE_IFRAME = 'iframe'
const POPUP_TYPE_POPUP  = 'popup'
const POPUP_TYPE = POPUP_TYPE_IFRAME; // "iframe" or "popup" is possible
```

**Code Evidence** (`content.js`, lines 2-100):
```javascript
const MenuIframe =
{
	inject: function (p) {
		if (0 === (this.$instance = $("#__pdfxcnangeMenuDialog__")).length) {
			this.$instance = $("<iframe>")
				.attr("id", "__pdfxcnangeMenuDialog__")
				.css({
					'border': '0px',
					'zIndex': 2147483647,
					'position': 'fixed',
					'top': '-1px',
					'right': '80px',
					'width': '294px',
					'height': '165px',
					'display': 'block',
					'margin': 'auto',
					'boxShadow': '0 1px 4px #00000026'
				})
				.attr("src", chrome.runtime.getURL("menu-iframe/index.html?p=" + encodeURIComponent(JSON.stringify({
					doctype: p.doctype,
					tab_id: p.tab_id,
					init_with_progress: p.init_with_progress
				}))))
				.appendTo("html");
		}
	},
}
```

**Purpose**:
- When `POPUP_TYPE = POPUP_TYPE_IFRAME`, the extension menu appears as an injected iframe on the page
- When `POPUP_TYPE = POPUP_TYPE_POPUP`, standard Chrome popup is used
- Iframe mode allows persistent UI while navigating (doesn't close when clicking outside)
- Iframe source is `chrome.runtime.getURL()` (extension's own resource, not external)

**Web Accessible Resources** (manifest.json):
```json
"web_accessible_resources": [{
	"resources": [ "menu-iframe/index.html", "frame.html", "native-part-is-not-installed.html" ],
	"matches": [ "<all_urls>" ]
}]
```

**Security Considerations**:
- Iframe loads **extension's own HTML pages** (`menu-iframe/index.html`), not external content
- No postMessage vulnerabilities detected (messages validated for source)
- Iframe injected only on user action (clicking extension icon)
- Uses maximum z-index (2147483647) to stay on top, but this is expected for UI overlay

**Verdict**: **NOT MALICIOUS** - Standard technique for persistent extension UI, using only extension resources.

---

### 5. PDF Detection Widget
**Severity**: N/A (Legitimate Functionality)
**Files**:
- `/content.js` (lines 133-294)
- `/background.js` (lines 660-702)

**Analysis**:
The extension automatically shows a small "Open in PDF-XChange Editor" widget when the user visits a PDF file URL.

**Code Evidence** (`content.js`, lines 140-194):
```javascript
function injectOpenPDFIFrame(offset) {
	if (!offset || !offset.top || !offset.left && !offset.right)
		offset = { top: 56, right: 12 };
	const sURL = chrome.runtime.getURL("frame.html");
	if (0 === ($newiframe = $("#__pdfxcnangeNewDialog__")).length) {
		const css = {
			border: "0px",
			position: "fixed",
			top: offset.top + "px",
			right: offset.right + "px",
			width: WIDGET_WIDTH + "px",
			height: WIDGET_HEIGHT + "px",
			display: "block",
			zIndex: 10,
		}

		$newiframe = $("<iframe>")
			.attr("id", "__pdfxcnangeNewDialog__")
			.css(css)
			.attr("src", sURL)
			.appendTo("html");
	}
}
```

**Code Evidence** (`background.js`, lines 676-688):
```javascript
if (request.doctype == "application/pdf") {
	chrome.storage.sync.get(['showOpenPDFFrame'], function (result) {
		chrome.tabs.sendMessage(sender.tab.id, {
			content_op: "showOpenPDFIFrame",
			show: (typeof result.showOpenPDFFrame === "undefined") ? true : result.showOpenPDFFrame
		}).catch((err) => {
			console.warn(
				`Failed to send message to a tab ${sender.tab.id} with just loaded PDF document to show "Open in Editor" widget`,
				err
			);
		});
	});
}
```

**Trigger Conditions**:
1. Content script detects document type: `document.contentType === "application/pdf"`
2. User has not disabled the widget in settings
3. Small iframe widget injected at top-right of PDF viewer
4. Widget can be dragged to different positions

**User Control**:
- Setting stored in `chrome.storage.sync` with key `showOpenPDFFrame`
- Users can disable via checkbox in extension popup: "Show 'Open in PDF-XChange Editor'"
- Widget position persists across sessions (`OpenPDFFrameOffset`)

**Verdict**: **NOT MALICIOUS** - Convenience feature for PDF editing workflow, user-controllable.

---

## False Positive Patterns Identified

| Pattern | Location | Reason for FP | Actual Purpose |
|---------|----------|---------------|----------------|
| `chrome.tabs.query → fetch` | `background.js:206,379` | Looks like data exfiltration | PDF download for local native app |
| `chrome.tabs.get → fetch` | `background.js:215,379` | Looks like data exfiltration | Tab info retrieval for PDF download |
| Iframe injection | `content.js:2-100` | Could be mistaken for malicious overlay | Extension's own popup UI |
| postMessage listeners | `content.js:238-286` | Could be mistaken for XSS vector | Internal message routing (validated source) |
| Web accessible resources | `manifest.json:46-49` | Could enable fingerprinting | UI components for extension popup |
| Base64 encoding | `background.js:414` | Could be mistaken for obfuscation | Required format for native messaging |

## Network Activity Analysis

### External Endpoints
**NONE** - The extension makes no external network requests.

### Data Flow Summary

**Data Sources**:
1. Current tab URL and title (for file naming)
2. Web page MHTML captures (via `chrome.pageCapture.saveAsMHTML()`)
3. PDF binary data downloaded from current tab URL (user-initiated)

**Data Destinations**:
1. Local native messaging host: `com.trackersoftware.htmltopdf`
2. Chrome storage APIs (`chrome.storage.local`, `chrome.storage.sync`)

**Data Collection**: Current tab URL/title only (for PDF conversion context)
**User Data Transmitted Externally**: NONE
**Tracking/Analytics**: NONE
**Third-Party Services**: NONE

**All operations are local-only**, communicating between:
- Chrome extension (browser context)
- Native PDF-XChange Editor application (desktop context)

## Permission Analysis

| Permission | Justification | Risk Level | Usage |
|------------|---------------|------------|-------|
| `pageCapture` | Capture web pages as MHTML for PDF conversion | Low (core feature) | `chrome.pageCapture.saveAsMHTML()` in `doHTMLToPDF()` |
| `nativeMessaging` | Communicate with local PDF-XChange Editor app | Low (local only) | `chrome.runtime.connectNative('com.trackersoftware.htmltopdf')` |
| `contextMenus` | Add "Convert to PDF" context menu | Low (functional) | Right-click menu item creation |
| `storage` | Save user preferences and widget positions | Low (local only) | `chrome.storage.sync` for settings |
| `tabs` | Access tab URL/title for PDF metadata | Low (functional) | `chrome.tabs.query()`, `chrome.tabs.get()` |
| `scripting` | Inject content scripts for UI overlays | Low (extension resources) | Content script injection for popup/widget |
| `host_permissions: <all_urls>` | Capture/convert any web page user visits | Medium (broad but necessary) | Required for pageCapture and content script injection |

**Assessment**: All permissions are justified and used appropriately for declared functionality. No excessive permissions detected.

## Content Security Policy
```json
No CSP declared in manifest.json (Manifest V3 default applies)
```
**Note**: Manifest V3 extensions have built-in CSP protections that prevent inline script execution and `eval()`.

## Code Quality Observations

### Positive Indicators
1. No dynamic code execution (`eval()`, `Function()`, `executeScript()` with code strings)
2. No external script loading
3. No XHR/fetch hooking or monkey-patching
4. No extension enumeration (`chrome.management` not used)
5. No residential proxy infrastructure
6. No market intelligence SDKs (Sensor Tower, Pathmatics, etc.)
7. No cookie harvesting
8. No ad/coupon injection
9. No remote config or kill switches
10. All injected iframes load extension's own resources via `chrome.runtime.getURL()`
11. Progressive error handling with user-facing alerts
12. Graceful degradation when native app not installed

### Obfuscation Level
**Minimal** - Code appears to be from a standard build process with no deliberate obfuscation. Variable names are readable, logic is straightforward.

### External Dependencies
- jQuery 3.4.1 (`libs/jquery-3.4.1.min.js`) - Standard library, loaded from extension bundle (not CDN)

## Comparison to Known Malicious Patterns

| Malicious Pattern | Present? | Evidence |
|-------------------|----------|----------|
| Extension enumeration/killing | ✗ No | No `chrome.management` API usage |
| XHR/fetch hooking | ✗ No | No prototype modifications detected |
| Residential proxy infrastructure | ✗ No | No proxy configuration |
| AI conversation scraping | ✗ No | No API interception |
| Market intelligence SDKs | ✗ No | No Sensor Tower, Pathmatics, etc. |
| Ad/coupon injection | ✗ No | No DOM manipulation for ads |
| Remote config/kill switches | ✗ No | No remote code loading |
| Cookie harvesting | ✗ No | No cookie API usage |
| GA/analytics proxy bypass | ✗ No | No analytics manipulation |
| Hidden data exfiltration | ✗ No | All data stays local or goes to native app |
| Credential theft | ✗ No | No form/password interception |
| Keylogging | ✗ No | No keyboard event listeners |
| Screen recording | ✗ No | No `chrome.tabCapture` video/audio streams |

## ext-analyzer Flow Analysis

### Flagged Flow 1: `chrome.tabs.query → fetch`
**Source**: `chrome.tabs.query({ currentWindow: true, active: true })`
**Sink**: `fetch(tabURL)`
**Verdict**: **FALSE POSITIVE**

**Reasoning**:
- `chrome.tabs.query()` retrieves active tab metadata (URL, title)
- `fetch(tabURL)` downloads PDF from the URL **the user is already viewing**
- Downloaded PDF is sent to **local native app**, not an external server
- User-initiated action (clicked "Open in PDF-XChange Editor")
- No sensitive data beyond current tab URL (already known to user)

### Flagged Flow 2: `chrome.tabs.get → fetch`
**Source**: `chrome.tabs.get(message.tab_id)`
**Sink**: `fetch(tabURL)`
**Verdict**: **FALSE POSITIVE**

**Reasoning**:
- Same as Flow 1, but uses `chrome.tabs.get()` instead of `chrome.tabs.query()`
- Alternative code path for popup vs iframe UI modes
- Same benign behavior: download PDF from current tab to pass to native app

### Why ext-analyzer Flagged These
The static analyzer correctly identified data flow patterns that **could** indicate exfiltration:
1. Sensitive source: Tab information (URLs can contain tokens, session IDs)
2. Network sink: `fetch()` makes HTTP requests

However, context analysis reveals:
- The `fetch()` call downloads from `tabURL` (the page the user is viewing)
- Downloaded data goes to native messaging, not external servers
- This is the **intended functionality** of a PDF editor bridge extension

## Overall Risk Assessment

### Risk Level: **CLEAN**

**Justification**:
1. **No malicious behavior detected** across all attack vectors
2. **No external network activity** - all operations are local or native app communication
3. **No data exfiltration** - extension only processes current page content as requested by user
4. **Transparent functionality** - all features match user expectations for a PDF editor integration
5. **No tracking or surveillance** mechanisms
6. **Legitimate business model** - commercial desktop software integration
7. **ext-analyzer flows are false positives** - downloading PDFs for local app, not data theft

### Recommendations
- **No action required** - Extension operates as advertised
- Users should understand this extension requires the desktop PDF-XChange Editor to be installed
- The extension will show alerts if native app is not found or blocked by admin policies

### User Privacy Impact
**MINIMAL** - The extension only accesses:
- Current tab URL and title (for PDF metadata)
- Page content when user clicks "Convert to PDF" (via Chrome's pageCapture API)
- No cross-site tracking or data aggregation
- No external servers contacted

## Technical Summary

**Lines of Code**: ~915 (primary background.js)
**External Dependencies**: jQuery 3.4.1 (bundled)
**Third-Party Libraries**: None beyond jQuery
**Remote Code Loading**: None
**Dynamic Code Execution**: None
**Native Messaging Host**: `com.trackersoftware.htmltopdf`

## Conclusion

PDF-XChange is a **clean, legitimate browser extension** that serves as a bridge between Chrome/Edge and the PDF-XChange Editor desktop application. The two "exfiltration flows" flagged by ext-analyzer are false positives arising from the extension's core functionality: downloading PDFs from the current tab URL to pass them to the local native application via Chrome's nativeMessaging API.

The extension makes **no external network requests** - all data flows are either:
1. Current page → Native app (for PDF conversion/opening)
2. Extension → Chrome storage (for user preferences)

No user data is collected, tracked, or transmitted to external servers. The extension's permissions are appropriate for its declared functionality, and code quality shows no signs of malicious intent or obfuscation.

**Final Verdict: CLEAN** - Safe for use with ~1M users.

---

## Appendix: Native Messaging Architecture

**How Native Messaging Works**:
1. User installs Chrome extension
2. User installs native PDF-XChange Editor desktop application
3. Desktop app installer creates a native messaging manifest file at OS-specific location:
   - Windows: `HKEY_CURRENT_USER\Software\Google\Chrome\NativeMessagingHosts\com.trackersoftware.htmltopdf`
   - macOS: `~/Library/Application Support/Google/Chrome/NativeMessagingHosts/com.trackersoftware.htmltopdf.json`
   - Linux: `~/.config/google-chrome/NativeMessagingHosts/com.trackersoftware.htmltopdf.json`
4. Manifest specifies:
   - Path to native app executable
   - Allowed Chrome extension IDs
5. Extension connects via `chrome.runtime.connectNative('com.trackersoftware.htmltopdf')`
6. Chrome spawns native app process and establishes bidirectional communication via stdin/stdout
7. Messages exchanged as JSON over standard streams

**Security Model**:
- Native app must be explicitly installed by user (not downloaded by extension)
- OS-level permissions required to install native messaging manifest
- Communication is local-only (no network layer)
- Chrome validates extension ID against manifest's allowed_origins
- Native app runs with user's OS permissions (not elevated)

This architecture prevents malicious extensions from communicating with arbitrary native applications without user consent and explicit installation.
