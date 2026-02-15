import type { InstalledExtensionInfo } from "@amibeingpwned/types";
import type { RiskLevel } from "@amibeingpwned/types";

export interface DemoPiece {
  extension: InstalledExtensionInfo;
  risk: RiskLevel;
}

export const demoPieces: DemoPiece[] = [
  {
    extension: { id: "cjpalhdlnbpafiamejdnhcphjbkeiagm", name: "uBlock Origin", enabled: true },
    risk: "clean",
  },
  {
    extension: { id: "nngceckbapebfimnlniiiahkandclblb", name: "Bitwarden", enabled: true },
    risk: "clean",
  },
  {
    extension: { id: "aapbdbdomjkkjkaonfhkkikfgjllcleb", name: "Google Translate", enabled: true },
    risk: "low",
  },
  {
    extension: { id: "bhhhlbepdkbapadjdnnojkbgioiodbic", name: "Honey", enabled: true },
    risk: "medium",
  },
  {
    extension: { id: "gcbommkclmhbkzddftdipkifpdlkjgal", name: "SusExt Pro", enabled: true },
    risk: "high",
  },
  {
    extension: { id: "fmkadmapgofadopljbjfkapdkoienihi", name: "React DevTools", enabled: true },
    risk: "clean",
  },
  {
    extension: { id: "eimadpbcbfnmbkopoojfekhnkhdbieeh", name: "Dark Reader", enabled: true },
    risk: "low",
  },
  {
    extension: { id: "mlomiejdfkolichcflejclcbmpeaniij", name: "Ghostery", enabled: true },
    risk: "medium-high",
  },
  {
    extension: { id: "hokifickgkhplphjiodbggjmoafhignh", name: "MalSniff", enabled: true },
    risk: "critical",
  },
];
