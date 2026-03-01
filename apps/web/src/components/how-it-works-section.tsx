const INGESTION_OPTIONS = [
  {
    label: "Google Workspace",
    tag: "Managed fleets",
    desc: "Connect via the Chrome Management API. Pulls extension data across your entire org with no per-device setup.",
    pros: ["Instant fleet-wide coverage", "No software to install"],
    cons: ["Requires Google Workspace + Chrome management"],
  },
  {
    label: "Chrome Extension",
    tag: "Any browser",
    desc: "Install the lightweight extension on each machine. Works on personal or unmanaged devices Google can't see.",
    pros: ["No Workspace subscription needed", "Covers BYOD & unmanaged devices"],
    cons: ["Must be installed per device", "Needs an admin invite link"],
  },
] as const;

const STEPS = [
  {
    step: "02",
    title: "Automated risk analysis",
    desc: "We use static analysis, LLM agents, and human expertise to identify problematic extensions - looking at permissions, behaviour, and known threat intelligence.",
  },
  {
    step: "03",
    title: "Actionable reports",
    desc: "Get risk-scored results with plain-English explanations. Block, replace, or monitor extensions - with evidence you can share with stakeholders.",
  },
] as const;

export function HowItWorksSection() {
  return (
    <section id="how-it-works" className="mx-auto max-w-6xl px-6 py-16">
      <h2 className="text-foreground mb-2 text-xl font-semibold">
        How it works
      </h2>
      <p className="text-muted-foreground mb-12 text-sm">
        Turn around your browser security in under 48 hours, with no deployment
        or maintenance overhead.
      </p>

      {/* Step 01 - two ingestion options */}
      <div className="mb-10">
        <span className="text-primary mb-3 block font-mono text-xs font-semibold tracking-widest">
          01
        </span>
        <h3 className="text-foreground mb-1 text-sm font-semibold">
          Connect your inventory
        </h3>
        <p className="text-muted-foreground mb-5 text-xs leading-relaxed">
          Two ways to share your extension list - pick whichever fits your
          setup. Only extension IDs and metadata leave the device; no browsing
          history or personal data.
        </p>

        <div className="grid gap-3 sm:grid-cols-2">
          {INGESTION_OPTIONS.map((opt) => (
            <div
              key={opt.label}
              className="bg-card border-border rounded-lg border p-4"
            >
              <div className="mb-2 flex items-center gap-2">
                <span className="text-foreground text-xs font-semibold">
                  {opt.label}
                </span>
                <span className="bg-muted text-muted-foreground rounded-full px-2 py-0.5 text-[10px]">
                  {opt.tag}
                </span>
              </div>
              <p className="text-muted-foreground mb-3 text-xs leading-relaxed">
                {opt.desc}
              </p>
              <ul className="space-y-1 text-[11px]">
                {opt.pros.map((p) => (
                  <li key={p} className="text-foreground/70 flex gap-1.5">
                    <span className="text-emerald-500">+</span> {p}
                  </li>
                ))}
                {opt.cons.map((c) => (
                  <li key={c} className="text-muted-foreground flex gap-1.5">
                    <span className="text-red-400">-</span> {c}
                  </li>
                ))}
              </ul>
            </div>
          ))}
        </div>
      </div>

      {/* Steps 02 + 03 */}
      <div className="grid gap-8 sm:grid-cols-2">
        {STEPS.map((item) => (
          <div key={item.step} className="flex flex-col gap-3">
            <span className="text-primary font-mono text-xs font-semibold tracking-widest">
              {item.step}
            </span>
            <h3 className="text-foreground text-sm font-semibold">
              {item.title}
            </h3>
            <p className="text-muted-foreground text-xs leading-relaxed">
              {item.desc}
            </p>
          </div>
        ))}
      </div>
    </section>
  );
}
