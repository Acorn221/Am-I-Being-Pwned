export interface PermAnnotation {
  /** Matches the permission chip text, e.g. "cookies" */
  permission: string;
  /** Short label, e.g. "Cookie Theft" */
  title: string;
  /** Brief explanation, e.g. "Reads & exfiltrates session cookies" */
  description: string;
}

export interface HeroSlide {
  phrase: string;
  extensionId: string;
  /** Anonymised display name shown on the hero card (we can't name real extensions yet) */
  anonName: string;
  annotations?: PermAnnotation[];
}

/**
 * Each slide pairs a typing phrase with a specific extension from the database.
 * The phrase describes the extension category; the card shows the real data.
 *
 * Annotations focus on what the extension ACTUALLY DOES to the user — concrete,
 * verifiable behaviours from our vulnerability reports. We never speculate about
 * intent (e.g. "sold") — only state what the code does and where data goes.
 *
 * Ordered to lead with the most shocking examples and highest user counts.
 * Data sourced from our vulnerability reports in /website-reports/.
 */
export const HERO_SLIDES: HeroSlide[] = [
  {
    // phrase: "ad blocker",
    phrase: "browser extension",
    anonName: "Ad Block Plus Pro",
    extensionId: "gbdjcgalliefpinpmggefbloehmmknca", annotations: [
      { permission: "tabs", title: "Every URL Uploaded", description: "Every page you visit is sent to a remote server with a persistent tracking UUID" },
      { permission: "<all_urls>", title: "Cross-Device Tracking", description: "Your tracking ID syncs across all your devices via chrome.storage.sync" },
    ],
  },
  {
    // phrase: "VPN proxy",
    phrase: "free VPN",
    anonName: "Free VPN Unlimited",
    extensionId: "adlpodnneegcnbophopdmhedicjbcgco", annotations: [
      { permission: "proxy", title: "You're an Exit Node", description: "Unknown traffic is routed through your home connection as a residential proxy" },
      { permission: "management", title: "Kills Other Extensions", description: "Silently disables every other VPN so you can't switch away" },
      { permission: "cookies", title: "Shopping Hijacked", description: "Injects affiliate codes into your purchases via a third-party ad network" },
    ],
  },
  {
    // phrase: "website finder",
    phrase: "search tool",
    anonName: "Similar Sites Finder",
    extensionId: "necpbmbhhdiplmfhmjicabdeighkndkn", annotations: [
      { permission: "webRequest", title: "File Uploads Intercepted", description: "Documents you upload can be silently forwarded to a server-configured domain" },
      { permission: "tabs", title: "Encrypted Exfiltration", description: "Collected data is RSA+AES encrypted before being sent to a remote server" },
    ],
  },
  {
    // phrase: "ad skip tool",
    phrase: "ad blocker",
    anonName: "Ad Speedup & Skipper",
    extensionId: "pcjlckhhhmlefmobnnoolakplfppdchi", annotations: [
      { permission: "tabs", title: "ChatGPT Sessions Stolen", description: "Creates hidden ChatGPT tabs to hijack your access tokens and prompts" },
      { permission: "*://*/*", title: "Residential Proxy Botnet", description: "Your browser becomes a proxy node via a remote command server" },
    ],
  },
  {
    // phrase: "screen timer",
    phrase: "screen time tracker",
    anonName: "Screen Time Tracker",
    extensionId: "elfaihghhjjoknimpccccmkioofjjfkf", annotations: [
      { permission: "*://*/*", title: "Ad Intelligence Sensor", description: "Embeds a data broker's SDK to scrape ads from every page you visit" },
      { permission: "tabs", title: "AI Chats Uploaded", description: "Your ChatGPT, Gemini & Copilot prompts are sent to a data broker's servers" },
    ],
  },
  {
    // phrase: "Twitter tool",
    phrase: "social media tool",
    anonName: "Tweet Manager Pro",
    extensionId: "amoldiondpmjdnllknhklocndiibkcoe", annotations: [
      { permission: "cookies", title: "Session Stolen", description: "Reads your auth cookies to make API calls as you" },
      { permission: "webRequest", title: "Credential Harvesting", description: "Intercepts login requests to capture your credentials" },
    ],
  },
  {
    // phrase: "one-click VPN",
    phrase: "VPN extension",
    anonName: "1-Click VPN Free",
    extensionId: "fcfhplploccackoneaefokcmbjfbkenj", annotations: [
      { permission: "proxy", title: "You Are the VPN", description: "Your home internet is used as a proxy to route strangers' traffic" },
      { permission: "webRequest", title: "Ads Injected", description: "Injects ads into pages you visit to generate revenue" },
    ],
  },
  {
    // phrase: "video editor",
    phrase: "media editor",
    anonName: "Movie Maker Studio",
    extensionId: "ohgkmilcibaoempgifldidkidnbkbeii", annotations: [
      { permission: "tabs", title: "Every Site Reported", description: "Every URL you visit is hex-encoded and sent to a remote tracking server" },
      { permission: "storage", title: "Permanent Tracking ID", description: "A unique ID stored in chrome.storage.sync follows you across devices" },
    ],
  },
  {
    phrase: "new tab page",
    anonName: "Infinite New Tab",
    extensionId: "meffljleomgifbbcffejnmhjagncfpbd", annotations: [
      { permission: "topSites", title: "Top Sites Harvested", description: "Your most-visited sites are collected and sent to a remote server" },
      { permission: "<all_urls>", title: "ChatGPT Cookies Extracted", description: "Reads all your ChatGPT cookies to make API calls on your behalf" },
    ],
  },
  {
    phrase: "notepad",
    anonName: "Notepad Online",
    extensionId: "fefodpegbocmidnfphgggnjcicipaibk", annotations: [
      { permission: "unlimitedStorage", title: "All Local Data Sent", description: "Your entire localStorage is dumped and uploaded to a remote server" },
      { permission: "storage", title: "Tracked Until 2033", description: "A tracking cookie is set to expire in 10+ years" },
    ],
  },
  {
    // phrase: "office suite",
    phrase: "document editor",
    anonName: "Office Online Suite",
    extensionId: "aobjedggladklcfbokddfgjkfdioknak", annotations: [
      { permission: "tabs", title: "Browsing History Uploaded", description: "Every URL you visit is hex-encoded and sent to a remote tracking server" },
      { permission: "storage", title: "Remote Tab Redirect", description: "The server can force your active tab to navigate to a different URL" },
    ],
  },
  {
    // phrase: "audio editor",
    phrase: "audio tool",
    anonName: "Audio Editor Studio",
    extensionId: "dfmpaemifkgbnlgcccccnfjjkeiikeie", annotations: [
      { permission: "tabs", title: "Full Surveillance", description: "Every page you visit is reported to a remote server in real time" },
      { permission: "storage", title: "Remote Tab Redirect", description: "Server responses can force your active tab to navigate elsewhere" },
    ],
  },
  {
    // phrase: "YouTube tool",
    phrase: "video tool",
    anonName: "Auto Ad Skipper",
    extensionId: "hmbnhhcgiecenbbkgdoaoafjpeaboine", annotations: [
      { permission: "declarativeNetRequest", title: "Remote Control Server", description: "Receives commands from a remote server to execute on your browser" },
      { permission: "<all_urls>", title: "Runs on Every Site", description: "Injected into all websites — far beyond its stated purpose" },
    ],
  },
  {
    phrase: "video downloader",
    anonName: "Video Downloader HD",
    extensionId: "penndbmahnpapepljikkjmakcobdahne", annotations: [
      { permission: "<all_urls>", title: "Keylogging Code Found", description: "Contains keylogging and XHR hooking code in its source" },
      { permission: "tabs", title: "Ads Injected", description: "Injects ads and affiliate links across sites you visit" },
    ],
  },
];
