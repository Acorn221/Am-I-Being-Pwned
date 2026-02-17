# Vulnerability Report: Notta: AI Meeting Notetaker & Audio Transcription

## Metadata
- **Extension ID**: kdelkaogljjcbjffjmahedaobfjineig
- **Extension Name**: Notta: AI Meeting Notetaker & Audio Transcription
- **Version**: 2.3.6
- **Users**: Unknown
- **Manifest Version**: 3
- **Analysis Date**: 2026-02-15

## Executive Summary

Notta is an AI-powered meeting transcription service that captures audio from browser tabs, Google Meet sessions, and YouTube videos to provide real-time transcription and AI-generated summaries. The extension requires extensive permissions including `tabCapture` for audio recording, `cookies` for authentication with the Notta backend, and content scripts on `<all_urls>` to inject transcription UI components.

The extension operates as disclosed: it captures audio streams, encodes them to Opus format, and uploads the data to Notta's backend servers (notta.io/notta.ai domains) for transcription processing. While the data transmission pattern appears to be "exfiltration" from a technical perspective, this is the explicit and disclosed purpose of the extension. Users install this extension specifically to send their audio data to Notta's servers for transcription.

## Vulnerability Details

### 1. LOW: PostMessage Handlers Without Origin Validation

**Severity**: LOW
**Files**: opusEncoderWorker.min.js:30818, assets/permissions-CZg1q99O.js:101
**CWE**: CWE-942 (Permissive Cross-domain Policy with Untrusted Domains)
**Description**: Two window.addEventListener("message") handlers do not validate the origin of received messages, potentially allowing malicious web pages to send crafted messages to the extension context.

**Evidence**:
```javascript
// opusEncoderWorker.min.js:30818
window.addEventListener("message", async (event) => {
  const { message } = event.data;
  // No origin check before processing event.data
```

```javascript
// assets/permissions-CZg1q99O.js:101
window.addEventListener("message", async (event) => {
  const { message } = event.data;
  if (message === "requestMicrophoneAccess") {
    try {
      await navigator.mediaDevices.getUserMedia({ audio: true });
    } catch (error) {
      n.error(error);
    }
  }
});
```

**Verdict**: The permissions.html handler only responds to a simple "requestMicrophoneAccess" message with no sensitive data exposed. The Opus encoder worker is processing audio encoding commands. While origin validation would be a best practice, the actual exploitability is limited since these handlers don't expose sensitive functionality or data without additional user consent (microphone permission prompt).

### 2. LOW: Disclosed Audio Data Transmission to Third-Party Servers

**Severity**: LOW
**Files**: assets/offscreen-uZ_HNXKr.js, assets/index-DInUc9wv.js, assets/indexeddb.worker-BlB6QGLZ.js
**CWE**: CWE-200 (Exposure of Sensitive Information to an Unauthorized Actor)
**Description**: The extension captures audio from browser tabs, Google Meet sessions, and microphone input, then transmits this data to Notta's backend servers for transcription. Audio is encoded to Opus format and uploaded to AWS S3 buckets via the Notta API gateway.

**Evidence**:
```javascript
// Starts streaming transcription session
const { data, code } = await startStreamingMediaTranscribe({
  uid: this.userInfo.uid,
  workspace_id: workspace,
  record_title: title,
  transcribe_language: language,
  audio_transmission_type: AUDIO_TRANSPORT_METHOD.KINESIS,
  audio_encoding_type: AUDIO_ENCODING_TYPE.OPUS
});
```

```javascript
// API endpoints contacted
const request$3 = wrapperRequest("https://apigateway-notta-service-ap.notta.io");
const request$2 = wrapperRequest("https://apigateway-notta-goods-interest-center-ap.notta.io");
```

```javascript
// S3 upload for audio files
const _2 = `https://s3.${S2}.amazonaws.com/${d2}/${n2}`;
```

**Verdict**: This behavior is the core, disclosed functionality of the extension. The extension description explicitly states "Instantly capture and transcribe audio from any browser tab or Google Meet into accurate, actionable text with Notta." Users install this extension with the explicit intent of sending audio to Notta's servers. The extension properly authenticates via cookies from app.notta.ai and syncs user account information. This is NOT malicious data exfiltration but rather a disclosed cloud service feature.

## False Positives Analysis

**Webpack-bundled Code Flagged as Obfuscated**: The ext-analyzer tool flagged the extension as "obfuscated," but examination reveals this is standard Vite/Webpack bundling with minimization. Files like `opusEncoderWorker.min.js` are legitimately minified production builds, not intentionally obfuscated malware. The deobfuscated source shows clear variable names and standard React/TypeScript patterns.

**Audio Capture as "Exfiltration"**: The static analyzer correctly identifies audio data flows to network sinks, but in this context, it's the intended service functionality. The extension is a cloud-based transcription service - sending audio data to servers is not a security flaw but the product feature.

**Cookie Access**: The extension accesses cookies from `app.notta.ai` to synchronize user authentication state between the web app and extension. This is standard authentication for browser extensions that integrate with web services.

## API Endpoints Analysis

| Endpoint | Purpose | Data Sent | Risk |
|----------|---------|-----------|------|
| apigateway-notta-service-ap.notta.io | Core transcription service | Audio streams, transcription requests, user workspace data | Low - disclosed service |
| apigateway-notta-goods-interest-center-ap.notta.io | Subscription/billing service | User balance, subscription tier queries | Low - account management |
| apigateway-mc-config-center-ap.notta.io | Configuration/encryption keys | Public key requests for S3 uploads | Low - infrastructure |
| notta-notify.notta.io | Notification service | WebSocket notifications for transcription completion | Low - UI notifications |
| app.notta.ai | Main web application | Cookie sync, authentication tokens | Low - authentication |
| s3.*.amazonaws.com | AWS S3 storage | Encrypted audio files, transcripts | Low - cloud storage backend |
| api.country.is | Geolocation service | IP-based country detection | Low - locale detection |
| www.google-analytics.com | Analytics | Usage analytics, install events | Low - standard analytics |

## Overall Risk Assessment

**RISK LEVEL: LOW**

**Justification**: This is a legitimate, professionally developed AI transcription service with expected permissions and data flows for its stated purpose. The extension clearly discloses that it captures and processes audio data through Notta's cloud services. All permissions requested (tabCapture, cookies, storage, notifications, offscreen) are necessary and appropriate for the functionality:

- `tabCapture` - Required to capture audio from browser tabs
- `cookies` - Used for authentication sync with app.notta.ai
- `storage` - Stores user preferences and session state
- `notifications` - Alerts users when transcription is complete
- `offscreen` - Processes audio encoding in background context

The postMessage origin validation issue is minor and does not expose sensitive data or functionality. The extension follows security best practices including using Manifest V3, proper CSP configuration, and encrypted HTTPS for all API communications.

Users should be aware that installing this extension grants Notta access to audio from any tab or meeting, which is sent to their servers for processing. This is disclosed in the extension description and privacy policy. For users concerned about privacy, this would not be an appropriate extension, but it is not malicious or deceptive about its data collection practices.
