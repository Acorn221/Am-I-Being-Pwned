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
  annotations?: PermAnnotation[];
}

/**
 * Each slide pairs a typing phrase with a specific extension from the database.
 * The phrase describes the extension category; the card shows the real data.
 */
export const HERO_SLIDES: HeroSlide[] = [
  {
    phrase: "free VPN",
    extensionId: "fcfhplploccackoneaefokcmbjfbkenj", // Free VPN 1clickvpn (high)
    annotations: [
      { permission: "proxy", title: "Proxy Control", description: "Routes your traffic through their servers" },
      { permission: "webRequest", title: "Network Interception", description: "Can read & modify all web requests" },
    ],
  },
  { phrase: "ad blocker", extensionId: "cfhdojbkjhnklbpkdaibdccddilifddb" }, // Adblock Plus (clean)
  {
    phrase: "productivity app",
    extensionId: "laankejkbhbdhmipfmgcngdelahlfoji", // StayFocusd (critical)
    annotations: [
      { permission: "tabs", title: "Tab Surveillance", description: "Monitors every site you visit" },
    ],
  },
  {
    phrase: "PDF converter",
    extensionId: "kdpelmjpfafjppnhbloffcjpeomlnpah", // WPS PDF (medium)
    annotations: [
      { permission: "cookies", title: "Cookie Access", description: "Reads session cookies from all sites" },
      { permission: "nativeMessaging", title: "System Access", description: "Communicates with programs on your computer" },
    ],
  },
  {
    phrase: "email tracker",
    extensionId: "bnompdfnhdbgdaoanapncknhmckenfog", // Email Tracker (high)
    annotations: [
      { permission: "cookies", title: "Cookie Theft", description: "Reads & exfiltrates session cookies" },
      { permission: "tabs", title: "Browsing Spy", description: "Tracks every page you open" },
    ],
  },
  {
    phrase: "browser theme",
    extensionId: "meffljleomgifbbcffejnmhjagncfpbd", // Infinite Dashboard (critical)
    annotations: [
      { permission: "topSites", title: "Habit Profiling", description: "Harvests your most-visited sites" },
      { permission: "tabs", title: "Tab Tracking", description: "Monitors all open tabs in real time" },
    ],
  },
  {
    phrase: "download manager",
    extensionId: "ahmpjcflkgiildlgicmcieglgoilbfdp", // Free Download Manager (medium)
    annotations: [
      { permission: "cookies", title: "Cookie Access", description: "Reads session cookies from all sites" },
      { permission: "history", title: "History Harvesting", description: "Reads your full browsing history" },
    ],
  },
  {
    phrase: "video editor",
    extensionId: "ohgkmilcibaoempgifldidkidnbkbeii", // Movie maker (critical)
    annotations: [
      { permission: "tabs", title: "Tab Surveillance", description: "Monitors every site you visit" },
    ],
  },
  {
    phrase: "QR code reader",
    extensionId: "likadllkkidlligfcdhfnnbkjigdkmci", // QR Code Reader (high)
    annotations: [
      { permission: "tabs", title: "Tab Surveillance", description: "Monitors every site you visit" },
    ],
  },
  {
    phrase: "VPN proxy",
    extensionId: "adlpodnneegcnbophopdmhedicjbcgco", // Troywell VPN (high)
    annotations: [
      { permission: "proxy", title: "Proxy Control", description: "Routes your traffic through their servers" },
      { permission: "management", title: "Extension Control", description: "Can disable or remove other extensions" },
      { permission: "privacy", title: "Privacy Override", description: "Changes your browser privacy settings" },
    ],
  },
  {
    phrase: "translator",
    extensionId: "aopddeflghjljihihabdclejbojaomaf", // AnyDoc Translator (medium)
    annotations: [
      { permission: "clipboardWrite", title: "Clipboard Access", description: "Can write to your clipboard" },
      { permission: "cookies", title: "Cookie Access", description: "Reads session cookies from all sites" },
    ],
  },
  {
    phrase: "screenshot tool",
    extensionId: "elfaihghhjjoknimpccccmkioofjjfkf", // StayFree (critical)
    annotations: [
      { permission: "tabs", title: "Tab Surveillance", description: "Monitors every site you visit" },
      { permission: "*://*/*", title: "Full Page Access", description: "Can read & modify all web pages" },
    ],
  },
  {
    phrase: "YouTube tool",
    extensionId: "hmbnhhcgiecenbbkgdoaoafjpeaboine", // Autoskip for Youtube Ads (critical)
    annotations: [
      { permission: "declarativeNetRequest", title: "Request Control", description: "Intercepts & modifies network requests" },
      { permission: "<all_urls>", title: "All Sites Access", description: "Can run on every website you visit" },
    ],
  },
  { phrase: "security tool", extensionId: "fheoggkfdfchfphceeifdbepaooicaho" }, // McAfee WebAdvisor (clean)
  {
    phrase: "website finder",
    extensionId: "necpbmbhhdiplmfhmjicabdeighkndkn", // Similar Sites (high)
    annotations: [
      { permission: "webRequest", title: "Network Interception", description: "Can read & modify all web requests" },
      { permission: "tabs", title: "Tab Surveillance", description: "Monitors every site you visit" },
    ],
  },
];
