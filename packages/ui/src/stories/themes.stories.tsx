import type { Meta, StoryObj } from "@storybook/react";
import type { CSSProperties, ReactNode } from "react";

const meta = {
  title: "Themes",
  parameters: {
    layout: "fullscreen",
  },
} satisfies Meta;

export default meta;
type Story = StoryObj<typeof meta>;

// ---------------------------------------------------------------------------
// Theme definition
// ---------------------------------------------------------------------------

interface ThemeConfig {
  name: string;
  tagline: string;
  vars: Record<string, string>;
  /** Extra inline styles applied to the theme root (fonts, tracking, etc.) */
  rootStyle?: CSSProperties;
  /** Extra Tailwind classes on the card shell */
  cardClass?: string;
  /** Extra Tailwind classes on the inner preview area */
  previewClass?: string;
  /** Custom banner renderer */
  banner?: (name: string, tagline: string) => ReactNode;
  /** Custom decorations rendered inside the preview area */
  decorations?: ReactNode;
  /** Tailwind classes for stat cards */
  statCardClass?: string;
  /** Tailwind classes for buttons */
  btnClass?: string;
  /** Tailwind classes for outline buttons */
  btnOutlineClass?: string;
  /** Tailwind classes for the input */
  inputClass?: string;
  /** Tailwind classes for table rows */
  tableRowClass?: string;
  /** Tailwind classes for badges */
  badgeClass?: string;
  /** Use mono font for everything */
  mono?: boolean;
}

// ---------------------------------------------------------------------------
// Shared table data
// ---------------------------------------------------------------------------

const TABLE_ROWS = [
  { service: "LinkedIn", email: "j@ex.com", severity: "High", status: "Open" },
  { service: "Dropbox", email: "j@ex.com", severity: "Med", status: "Fixed" },
  { service: "Adobe", email: "j@ex.com", severity: "Low", status: "Open" },
];

// ---------------------------------------------------------------------------
// Theme definitions
// ---------------------------------------------------------------------------

const themes: ThemeConfig[] = [
  // 1 ─ Glassmorphic Noir
  {
    name: "Glassmorphic Noir",
    tagline: "Frosted glass panels. Premium, modern.",
    vars: {
      "--background": "oklch(0.08 0.01 250)",
      "--foreground": "oklch(0.95 0.005 250)",
      "--card": "oklch(0.15 0.015 250 / 0.45)",
      "--card-foreground": "oklch(0.95 0.005 250)",
      "--primary": "oklch(0.72 0.14 195)",
      "--primary-foreground": "oklch(0.10 0 0)",
      "--secondary": "oklch(0.20 0.02 250 / 0.6)",
      "--secondary-foreground": "oklch(0.75 0.03 250)",
      "--muted": "oklch(0.20 0.01 250 / 0.5)",
      "--muted-foreground": "oklch(0.60 0.02 250)",
      "--accent": "oklch(0.25 0.04 195 / 0.4)",
      "--accent-foreground": "oklch(0.72 0.14 195)",
      "--destructive": "oklch(0.55 0.20 15)",
      "--destructive-foreground": "oklch(1 0 0)",
      "--border": "oklch(0.90 0.01 250 / 0.10)",
      "--input": "oklch(0.18 0.01 250 / 0.5)",
      "--ring": "oklch(0.72 0.14 195)",
      "--radius": "1rem",
      "--shadow-md": "0 8px 32px oklch(0.72 0.14 195 / 0.08)",
    },
    cardClass: "border border-white/10 rounded-2xl overflow-hidden",
    previewClass: "backdrop-blur-xl",
    statCardClass: "backdrop-blur-md border border-white/10 rounded-xl",
    btnClass: "rounded-xl",
    btnOutlineClass: "rounded-xl border-white/15",
    inputClass: "rounded-xl backdrop-blur-md border-white/10",
    banner: (name, tagline) => (
      <div
        className="relative h-28 p-5 overflow-hidden"
        style={{
          background:
            "linear-gradient(135deg, oklch(0.15 0.03 250), oklch(0.20 0.05 195), oklch(0.12 0.04 280))",
        }}
      >
        {/* Mesh gradient blobs */}
        <div
          className="absolute -top-10 -right-10 h-40 w-40 rounded-full opacity-30 blur-3xl"
          style={{ background: "oklch(0.72 0.14 195)" }}
        />
        <div
          className="absolute -bottom-10 -left-10 h-32 w-32 rounded-full opacity-20 blur-3xl"
          style={{ background: "oklch(0.60 0.15 280)" }}
        />
        <div className="relative z-10">
          <h3 className="text-xl font-semibold text-white drop-shadow-lg">{name}</h3>
          <p className="text-sm text-white/70 mt-1">{tagline}</p>
        </div>
      </div>
    ),
  },

  // 2 ─ Terminal
  {
    name: "Terminal",
    tagline: "Monospace everything. Raw data console.",
    mono: true,
    vars: {
      "--background": "oklch(0.0 0 0)",
      "--foreground": "oklch(0.80 0.18 145)",
      "--card": "oklch(0.05 0.01 145)",
      "--card-foreground": "oklch(0.80 0.18 145)",
      "--primary": "oklch(0.75 0.20 145)",
      "--primary-foreground": "oklch(0.0 0 0)",
      "--secondary": "oklch(0.10 0.02 145)",
      "--secondary-foreground": "oklch(0.65 0.12 145)",
      "--muted": "oklch(0.10 0.01 145)",
      "--muted-foreground": "oklch(0.50 0.08 145)",
      "--accent": "oklch(0.12 0.03 85)",
      "--accent-foreground": "oklch(0.78 0.15 85)",
      "--destructive": "oklch(0.55 0.18 85)",
      "--destructive-foreground": "oklch(0.0 0 0)",
      "--border": "oklch(0.25 0.06 145)",
      "--input": "oklch(0.05 0.01 145)",
      "--ring": "oklch(0.75 0.20 145)",
      "--radius": "0px",
      "--tracking-normal": "0.05em",
    },
    rootStyle: { fontFamily: "'Courier New', 'Consolas', monospace" },
    cardClass: "border border-green-500/40 rounded-none overflow-hidden",
    previewClass: "relative",
    statCardClass: "border border-green-500/30 rounded-none",
    btnClass: "rounded-none uppercase tracking-wider text-[10px]",
    btnOutlineClass: "rounded-none border-green-500/40 uppercase tracking-wider text-[10px]",
    inputClass: "rounded-none border-green-500/30",
    banner: (name, tagline) => (
      <div
        className="relative h-28 p-5 overflow-hidden border-b border-green-500/30"
        style={{ background: "oklch(0.03 0.01 145)" }}
      >
        {/* Scanlines */}
        <div
          className="absolute inset-0 opacity-[0.04] pointer-events-none"
          style={{
            backgroundImage:
              "repeating-linear-gradient(0deg, transparent, transparent 2px, oklch(0.75 0.20 145) 2px, oklch(0.75 0.20 145) 3px)",
          }}
        />
        <div className="relative z-10 font-mono">
          <div className="text-green-400/60 text-xs mb-1">$ cat /etc/theme</div>
          <h3 className="text-xl font-bold text-green-400 tracking-wider">
            {">"} {name}
            <span className="animate-pulse ml-1">_</span>
          </h3>
          <p className="text-sm text-green-400/50 mt-1 tracking-wide"># {tagline}</p>
        </div>
      </div>
    ),
    decorations: (
      <div
        className="absolute inset-0 opacity-[0.03] pointer-events-none z-0"
        style={{
          backgroundImage:
            "repeating-linear-gradient(0deg, transparent, transparent 2px, oklch(0.75 0.20 145) 2px, oklch(0.75 0.20 145) 3px)",
        }}
      />
    ),
  },

  // 3 ─ Brutalist Alert
  {
    name: "Brutalist Alert",
    tagline: "Thick borders. Bold type. No nonsense.",
    vars: {
      "--background": "oklch(0.06 0 0)",
      "--foreground": "oklch(0.93 0.01 80)",
      "--card": "oklch(0.10 0 0)",
      "--card-foreground": "oklch(0.93 0.01 80)",
      "--primary": "oklch(0.65 0.24 30)",
      "--primary-foreground": "oklch(0.0 0 0)",
      "--secondary": "oklch(0.20 0 0)",
      "--secondary-foreground": "oklch(0.80 0 0)",
      "--muted": "oklch(0.18 0 0)",
      "--muted-foreground": "oklch(0.55 0 0)",
      "--accent": "oklch(0.78 0.17 85)",
      "--accent-foreground": "oklch(0.0 0 0)",
      "--destructive": "oklch(0.60 0.26 25)",
      "--destructive-foreground": "oklch(1 0 0)",
      "--border": "oklch(0.80 0 0)",
      "--input": "oklch(0.10 0 0)",
      "--ring": "oklch(0.65 0.24 30)",
      "--radius": "0.25rem",
    },
    cardClass: "border-[3px] border-white/80 rounded-sm overflow-hidden",
    statCardClass: "border-2 border-white/60 rounded-sm",
    btnClass: "rounded-sm font-black uppercase tracking-wider text-[10px] border-2 border-black",
    btnOutlineClass: "rounded-sm font-black uppercase tracking-wider text-[10px] border-2",
    inputClass: "rounded-sm border-2 border-white/60",
    banner: (name, tagline) => (
      <div
        className="relative h-28 p-5 overflow-hidden"
        style={{
          background: "oklch(0.65 0.24 30)",
        }}
      >
        <div className="relative z-10">
          <h3 className="text-2xl font-black text-black uppercase tracking-widest">
            {name}
          </h3>
          <p className="text-sm font-bold text-black/70 uppercase tracking-wider mt-1">
            {tagline}
          </p>
        </div>
        {/* Hard shadow block accent */}
        <div
          className="absolute bottom-0 right-0 w-24 h-24 translate-x-6 translate-y-6"
          style={{
            background: "oklch(0.78 0.17 85)",
            boxShadow: "inset -4px -4px 0 oklch(0.0 0 0)",
          }}
        />
      </div>
    ),
    rootStyle: { fontWeight: "600" },
  },

  // 4 ─ Midnight Luxe
  {
    name: "Midnight Luxe",
    tagline: "Dark premium. Gold accents. Refined.",
    vars: {
      "--background": "oklch(0.07 0.005 60)",
      "--foreground": "oklch(0.90 0.01 60)",
      "--card": "oklch(0.11 0.008 60)",
      "--card-foreground": "oklch(0.90 0.01 60)",
      "--primary": "oklch(0.75 0.14 80)",
      "--primary-foreground": "oklch(0.08 0 0)",
      "--secondary": "oklch(0.18 0.01 60)",
      "--secondary-foreground": "oklch(0.68 0.04 60)",
      "--muted": "oklch(0.16 0.008 60)",
      "--muted-foreground": "oklch(0.52 0.02 60)",
      "--accent": "oklch(0.20 0.04 80)",
      "--accent-foreground": "oklch(0.78 0.12 80)",
      "--destructive": "oklch(0.50 0.18 25)",
      "--destructive-foreground": "oklch(1 0 0)",
      "--border": "oklch(0.22 0.02 60)",
      "--input": "oklch(0.14 0.01 60)",
      "--ring": "oklch(0.75 0.14 80)",
      "--radius": "0.5rem",
      "--tracking-normal": "-0.01em",
    },
    rootStyle: { letterSpacing: "-0.01em" },
    cardClass: "border border-amber-900/20 rounded-xl overflow-hidden",
    statCardClass: "border border-amber-900/20 rounded-lg",
    btnClass: "rounded-lg",
    btnOutlineClass: "rounded-lg border-amber-900/30",
    inputClass: "rounded-lg border-amber-900/20",
    banner: (name, tagline) => (
      <div
        className="relative h-28 p-5 overflow-hidden"
        style={{
          background:
            "linear-gradient(135deg, oklch(0.12 0.02 60), oklch(0.18 0.04 80), oklch(0.10 0.02 40))",
        }}
      >
        {/* Gold shimmer line */}
        <div
          className="absolute top-0 left-0 right-0 h-[1px]"
          style={{
            background:
              "linear-gradient(90deg, transparent, oklch(0.75 0.14 80 / 0.6), transparent)",
          }}
        />
        <div className="relative z-10">
          <h3 className="text-xl font-light tracking-tight text-amber-200/90">{name}</h3>
          <p className="text-sm text-amber-200/40 mt-1 tracking-tight">{tagline}</p>
        </div>
        {/* Subtle gold glow */}
        <div
          className="absolute -bottom-8 right-8 h-24 w-24 rounded-full opacity-15 blur-2xl"
          style={{ background: "oklch(0.75 0.14 80)" }}
        />
      </div>
    ),
  },

  // 5 ─ Cyber Grid
  {
    name: "Cyber Grid",
    tagline: "Sci-fi HUD. Mission control. Angular.",
    vars: {
      "--background": "oklch(0.06 0.03 265)",
      "--foreground": "oklch(0.92 0.02 250)",
      "--card": "oklch(0.10 0.04 265)",
      "--card-foreground": "oklch(0.92 0.02 250)",
      "--primary": "oklch(0.70 0.20 250)",
      "--primary-foreground": "oklch(0.05 0 0)",
      "--secondary": "oklch(0.16 0.04 265)",
      "--secondary-foreground": "oklch(0.72 0.08 250)",
      "--muted": "oklch(0.14 0.03 265)",
      "--muted-foreground": "oklch(0.55 0.04 265)",
      "--accent": "oklch(0.22 0.08 330)",
      "--accent-foreground": "oklch(0.70 0.20 330)",
      "--destructive": "oklch(0.55 0.22 15)",
      "--destructive-foreground": "oklch(1 0 0)",
      "--border": "oklch(0.28 0.06 250)",
      "--input": "oklch(0.12 0.04 265)",
      "--ring": "oklch(0.70 0.20 250)",
      "--radius": "0.375rem",
    },
    cardClass: "border border-blue-500/30 rounded-md overflow-hidden relative",
    statCardClass: "border border-blue-500/25 rounded-md relative",
    btnClass: "rounded-md",
    btnOutlineClass: "rounded-md",
    inputClass: "rounded-md border-blue-500/25",
    banner: (name, tagline) => (
      <div
        className="relative h-28 p-5 overflow-hidden"
        style={{
          background:
            "linear-gradient(135deg, oklch(0.08 0.05 265), oklch(0.12 0.06 250), oklch(0.08 0.05 280))",
        }}
      >
        {/* Grid overlay */}
        <div
          className="absolute inset-0 opacity-[0.06] pointer-events-none"
          style={{
            backgroundImage: `linear-gradient(oklch(0.70 0.20 250) 1px, transparent 1px),
              linear-gradient(90deg, oklch(0.70 0.20 250) 1px, transparent 1px)`,
            backgroundSize: "20px 20px",
          }}
        />
        {/* Neon glow line */}
        <div
          className="absolute bottom-0 left-0 right-0 h-[2px]"
          style={{
            background:
              "linear-gradient(90deg, oklch(0.70 0.20 250), oklch(0.70 0.20 330), oklch(0.70 0.20 250))",
            boxShadow: "0 0 12px oklch(0.70 0.20 250 / 0.5)",
          }}
        />
        <div className="relative z-10">
          <div className="text-blue-400/50 text-[10px] font-mono uppercase tracking-widest mb-1">
            // System.Theme.Active
          </div>
          <h3 className="text-xl font-bold text-blue-300 tracking-wide">{name}</h3>
          <p className="text-sm text-blue-400/50 mt-1">{tagline}</p>
        </div>
      </div>
    ),
    decorations: (
      <>
        {/* Grid bg */}
        <div
          className="absolute inset-0 opacity-[0.03] pointer-events-none z-0"
          style={{
            backgroundImage: `linear-gradient(oklch(0.70 0.20 250) 1px, transparent 1px),
              linear-gradient(90deg, oklch(0.70 0.20 250) 1px, transparent 1px)`,
            backgroundSize: "24px 24px",
          }}
        />
        {/* Corner accents */}
        <div className="absolute top-2 left-2 w-3 h-3 border-t-2 border-l-2 border-blue-500/30 pointer-events-none z-10" />
        <div className="absolute top-2 right-2 w-3 h-3 border-t-2 border-r-2 border-blue-500/30 pointer-events-none z-10" />
        <div className="absolute bottom-2 left-2 w-3 h-3 border-b-2 border-l-2 border-blue-500/30 pointer-events-none z-10" />
        <div className="absolute bottom-2 right-2 w-3 h-3 border-b-2 border-r-2 border-blue-500/30 pointer-events-none z-10" />
      </>
    ),
  },

  // 6 ─ Paper Dark
  {
    name: "Paper Dark",
    tagline: "Minimal. Muted. Content-first editorial.",
    vars: {
      "--background": "oklch(0.12 0.005 60)",
      "--foreground": "oklch(0.85 0.01 80)",
      "--card": "oklch(0.15 0.006 60)",
      "--card-foreground": "oklch(0.85 0.01 80)",
      "--primary": "oklch(0.62 0.06 60)",
      "--primary-foreground": "oklch(0.10 0 0)",
      "--secondary": "oklch(0.20 0.008 60)",
      "--secondary-foreground": "oklch(0.68 0.02 60)",
      "--muted": "oklch(0.18 0.005 60)",
      "--muted-foreground": "oklch(0.50 0.015 60)",
      "--accent": "oklch(0.22 0.01 30)",
      "--accent-foreground": "oklch(0.62 0.06 30)",
      "--destructive": "oklch(0.50 0.14 20)",
      "--destructive-foreground": "oklch(0.90 0.01 80)",
      "--border": "oklch(0.22 0.008 60)",
      "--input": "oklch(0.16 0.005 60)",
      "--ring": "oklch(0.62 0.06 60)",
      "--radius": "0.5rem",
    },
    rootStyle: { fontFamily: "'Georgia', 'Times New Roman', serif" },
    cardClass: "border border-stone-700/30 rounded-lg overflow-hidden",
    statCardClass: "border border-stone-700/20 rounded-lg",
    btnClass: "rounded-lg",
    btnOutlineClass: "rounded-lg border-stone-700/30",
    inputClass: "rounded-lg border-stone-700/20",
    banner: (name, tagline) => (
      <div
        className="relative h-28 p-5 overflow-hidden"
        style={{
          background: "oklch(0.14 0.006 60)",
        }}
      >
        {/* Subtle paper texture */}
        <div
          className="absolute inset-0 opacity-[0.03] pointer-events-none"
          style={{
            backgroundImage: `url("data:image/svg+xml,%3Csvg width='6' height='6' xmlns='http://www.w3.org/2000/svg'%3E%3Cfilter id='n'%3E%3CfeTurbulence baseFrequency='0.9'/%3E%3C/filter%3E%3Crect width='100%25' height='100%25' filter='url(%23n)'/%3E%3C/svg%3E")`,
          }}
        />
        {/* Thin rule */}
        <div
          className="absolute bottom-0 left-5 right-5 h-[1px]"
          style={{ background: "oklch(0.30 0.01 60)" }}
        />
        <div className="relative z-10">
          <h3 className="text-2xl font-light text-stone-300 italic tracking-tight">{name}</h3>
          <p className="text-sm text-stone-500 mt-2">{tagline}</p>
        </div>
      </div>
    ),
  },
];

// ---------------------------------------------------------------------------
// Severity colors (using theme vars)
// ---------------------------------------------------------------------------

function severityStyle(sev: string) {
  switch (sev) {
    case "High":
      return {
        bg: "var(--destructive)",
        fg: "var(--destructive-foreground)",
      };
    case "Med":
      return { bg: "var(--primary)", fg: "var(--primary-foreground)" };
    default:
      return { bg: "var(--secondary)", fg: "var(--secondary-foreground)" };
  }
}

// ---------------------------------------------------------------------------
// ThemePreview component
// ---------------------------------------------------------------------------

function ThemePreview({ theme }: { theme: ThemeConfig }) {
  const fontBase: CSSProperties = theme.mono
    ? { fontFamily: "'Courier New', 'Consolas', monospace" }
    : {};

  return (
    <div
      className={theme.cardClass ?? "overflow-hidden rounded-xl border"}
      style={{
        ...(theme.vars as CSSProperties),
        ...fontBase,
        ...(theme.rootStyle ?? {}),
      }}
    >
      {/* Banner */}
      {theme.banner ? (
        theme.banner(theme.name, theme.tagline)
      ) : (
        <div className="relative h-28 p-5" style={{ background: "var(--primary)" }}>
          <h3 className="text-xl font-bold text-white">{theme.name}</h3>
          <p className="text-sm text-white/70 mt-1">{theme.tagline}</p>
        </div>
      )}

      {/* Preview area */}
      <div
        className={`relative space-y-4 p-5 ${theme.previewClass ?? ""}`}
        style={{
          backgroundColor: "var(--background)",
          color: "var(--foreground)",
        }}
      >
        {theme.decorations}

        {/* Color palette + radius preview */}
        <div className="relative z-10 flex items-center justify-between">
          <div className="flex gap-1.5">
            {[
              "--primary",
              "--accent",
              "--secondary",
              "--muted",
              "--destructive",
            ].map((v) => (
              <div
                key={v}
                className="h-5 w-5 rounded-full border border-white/10"
                style={{ backgroundColor: `var(${v})` }}
                title={v.replace("--", "")}
              />
            ))}
          </div>
          {/* Radius preview */}
          <div className="flex items-center gap-2 text-[10px]" style={{ color: "var(--muted-foreground)" }}>
            <span>radius:</span>
            <div
              className="h-5 w-8 border"
              style={{
                borderColor: "var(--border)",
                borderRadius: theme.vars["--radius"] ?? "0.5rem",
              }}
            />
          </div>
        </div>

        {/* Stat cards */}
        <div className="relative z-10 grid grid-cols-3 gap-2">
          {[
            { label: "Breaches", value: "12", delta: "+3" },
            { label: "Accounts", value: "47", delta: null },
            { label: "Risk", value: "High", delta: null },
          ].map((stat) => (
            <div
              key={stat.label}
              className={`p-2.5 ${theme.statCardClass ?? "border rounded-lg"}`}
              style={{
                backgroundColor: "var(--card)",
                color: "var(--card-foreground)",
                borderColor: undefined, // let class handle
              }}
            >
              <div
                className="text-[10px] mb-1"
                style={{ color: "var(--muted-foreground)" }}
              >
                {stat.label}
              </div>
              <div className="text-lg font-bold leading-none">{stat.value}</div>
              {stat.delta && (
                <div
                  className="text-[10px] mt-1 font-medium"
                  style={{ color: "var(--destructive)" }}
                >
                  {stat.delta}
                </div>
              )}
            </div>
          ))}
        </div>

        {/* Buttons row */}
        <div className="relative z-10 flex flex-wrap gap-2">
          <button
            className={`px-3 py-1.5 text-xs font-medium shadow-sm ${theme.btnClass ?? "rounded-md"}`}
            style={{
              backgroundColor: "var(--primary)",
              color: "var(--primary-foreground)",
              boxShadow: theme.name === "Brutalist Alert"
                ? "3px 3px 0 var(--foreground)"
                : theme.name === "Cyber Grid"
                  ? "0 0 10px oklch(0.70 0.20 250 / 0.3)"
                  : undefined,
            }}
          >
            {theme.mono ? "$ scan --now" : "Scan Now"}
          </button>
          <button
            className={`px-3 py-1.5 text-xs font-medium border ${theme.btnOutlineClass ?? "rounded-md"}`}
            style={{
              borderColor: "var(--border)",
              backgroundColor: "transparent",
              color: "var(--foreground)",
              boxShadow: theme.name === "Brutalist Alert" ? "3px 3px 0 var(--border)" : undefined,
            }}
          >
            View Report
          </button>
          <button
            className={`px-3 py-1.5 text-xs font-medium ${theme.btnClass ?? "rounded-md"}`}
            style={{
              backgroundColor: "var(--secondary)",
              color: "var(--secondary-foreground)",
            }}
          >
            Settings
          </button>
          <button
            className={`px-3 py-1.5 text-xs font-medium ${theme.btnClass ?? "rounded-md"}`}
            style={{
              backgroundColor: "transparent",
              color: "var(--muted-foreground)",
            }}
          >
            Ghost
          </button>
        </div>

        {/* Input */}
        <div className="relative z-10 space-y-1.5">
          <label
            className="text-xs font-medium"
            style={theme.name === "Brutalist Alert" ? { textTransform: "uppercase", letterSpacing: "0.05em" } : {}}
          >
            Email to monitor
          </label>
          <div
            className={`flex h-8 w-full items-center border px-2.5 text-xs ${theme.inputClass ?? "rounded-md"}`}
            style={{
              borderColor: "var(--border)",
              backgroundColor: "var(--input)",
              color: "var(--muted-foreground)",
            }}
          >
            {theme.mono ? "user@host:~$" : "you@example.com"}
          </div>
        </div>

        {/* Mini table */}
        <div
          className={`relative z-10 text-xs overflow-hidden ${theme.name === "Brutalist Alert" ? "border-2 rounded-sm" : "border rounded-lg"}`}
          style={{ borderColor: "var(--border)" }}
        >
          {/* Header */}
          <div
            className="flex items-center px-3 py-1.5 text-[10px] font-semibold uppercase tracking-wider"
            style={{
              backgroundColor: "var(--muted)",
              color: "var(--muted-foreground)",
              borderBottom: "1px solid var(--border)",
            }}
          >
            <span className="flex-1">Service</span>
            <span className="w-24">Email</span>
            <span className="w-14 text-center">Severity</span>
            <span className="w-12 text-right">Status</span>
          </div>
          {TABLE_ROWS.map((row, i) => {
            const sev = severityStyle(row.severity);
            return (
              <div
                key={row.service}
                className={`flex items-center px-3 py-1.5 ${theme.tableRowClass ?? ""}`}
                style={{
                  borderBottom:
                    i < TABLE_ROWS.length - 1
                      ? "1px solid var(--border)"
                      : "none",
                }}
              >
                <span className="flex-1 font-medium">{row.service}</span>
                <span className="w-24 truncate" style={{ color: "var(--muted-foreground)" }}>
                  {row.email}
                </span>
                <span className="w-14 flex justify-center">
                  <span
                    className="inline-block rounded-full px-1.5 py-0.5 text-[10px] font-medium"
                    style={{
                      backgroundColor: sev.bg,
                      color: sev.fg,
                    }}
                  >
                    {row.severity}
                  </span>
                </span>
                <span className="w-12 text-right text-[10px]" style={{ color: "var(--muted-foreground)" }}>
                  {row.status}
                </span>
              </div>
            );
          })}
        </div>

        {/* Badge row */}
        <div className="relative z-10 flex flex-wrap gap-1.5">
          {[
            { label: "Primary", bg: "--primary", fg: "--primary-foreground" },
            { label: "Secondary", bg: "--secondary", fg: "--secondary-foreground" },
            { label: "Accent", bg: "--accent", fg: "--accent-foreground" },
            { label: "Destructive", bg: "--destructive", fg: "--destructive-foreground" },
            { label: "Muted", bg: "--muted", fg: "--muted-foreground" },
          ].map((badge) => (
            <span
              key={badge.label}
              className={`inline-flex items-center px-2 py-0.5 text-[10px] font-medium ${theme.badgeClass ?? "rounded-full"}`}
              style={{
                backgroundColor: `var(${badge.bg})`,
                color: `var(${badge.fg})`,
              }}
            >
              {theme.mono ? `[${badge.label}]` : badge.label}
            </span>
          ))}
        </div>

        {/* Accent bar */}
        <div
          className="relative z-10 h-1 w-full"
          style={{
            borderRadius: theme.vars["--radius"] ?? "0.5rem",
            background:
              theme.name === "Cyber Grid"
                ? "linear-gradient(90deg, oklch(0.70 0.20 250), oklch(0.70 0.20 330))"
                : theme.name === "Terminal"
                  ? "oklch(0.75 0.20 145)"
                  : `linear-gradient(90deg, var(--primary), var(--accent-foreground))`,
            boxShadow:
              theme.name === "Cyber Grid"
                ? "0 0 8px oklch(0.70 0.20 250 / 0.4)"
                : undefined,
          }}
        />
      </div>
    </div>
  );
}

// ---------------------------------------------------------------------------
// Story
// ---------------------------------------------------------------------------

export const Gallery: Story = {
  render: () => (
    <div className="bg-background text-foreground min-h-screen p-8">
      <div className="mx-auto max-w-7xl space-y-8">
        <div className="space-y-2">
          <h1 className="text-4xl font-bold tracking-tight">Theme Gallery</h1>
          <p className="text-muted-foreground text-lg">
            Six distinct themes — each with unique shape, depth, typography, and feel.
          </p>
        </div>

        <div className="grid gap-8 lg:grid-cols-2">
          {themes.map((theme) => (
            <ThemePreview key={theme.name} theme={theme} />
          ))}
        </div>

        <div className="text-muted-foreground pb-8 text-center text-sm">
          Each theme varies in radius, shadows, typography, texture, and color palette.
        </div>
      </div>
    </div>
  ),
};
