export interface HeroSlide {
  phrase: string;
  extensionId: string;
}

/**
 * Each slide pairs a typing phrase with a specific extension from the database.
 * The phrase describes the extension category; the card shows the real data.
 */
export const HERO_SLIDES: HeroSlide[] = [
  { phrase: "free VPN", extensionId: "fcfhplploccackoneaefokcmbjfbkenj" }, // Free VPN 1clickvpn (high)
  { phrase: "ad blocker", extensionId: "cfhdojbkjhnklbpkdaibdccddilifddb" }, // Adblock Plus (clean)
  { phrase: "productivity app", extensionId: "laankejkbhbdhmipfmgcngdelahlfoji" }, // StayFocusd (critical)
  { phrase: "PDF converter", extensionId: "kdpelmjpfafjppnhbloffcjpeomlnpah" }, // WPS PDF (medium)
  { phrase: "email tracker", extensionId: "bnompdfnhdbgdaoanapncknhmckenfog" }, // Email Tracker (high)
  { phrase: "browser theme", extensionId: "meffljleomgifbbcffejnmhjagncfpbd" }, // Infinite Dashboard (critical)
  { phrase: "download manager", extensionId: "ahmpjcflkgiildlgicmcieglgoilbfdp" }, // Free Download Manager (medium)
  { phrase: "video editor", extensionId: "ohgkmilcibaoempgifldidkidnbkbeii" }, // Movie maker (critical)
  { phrase: "QR code reader", extensionId: "likadllkkidlligfcdhfnnbkjigdkmci" }, // QR Code Reader (high)
  { phrase: "VPN proxy", extensionId: "adlpodnneegcnbophopdmhedicjbcgco" }, // Troywell VPN (high)
  { phrase: "translator", extensionId: "aopddeflghjljihihabdclejbojaomaf" }, // AnyDoc Translator (medium)
  { phrase: "screenshot tool", extensionId: "elfaihghhjjoknimpccccmkioofjjfkf" }, // StayFree (critical)
  { phrase: "YouTube tool", extensionId: "hmbnhhcgiecenbbkgdoaoafjpeaboine" }, // Autoskip for Youtube Ads (critical)
  { phrase: "security tool", extensionId: "fheoggkfdfchfphceeifdbepaooicaho" }, // McAfee WebAdvisor (clean)
  { phrase: "website finder", extensionId: "necpbmbhhdiplmfhmjicabdeighkndkn" }, // Similar Sites (high)
];
