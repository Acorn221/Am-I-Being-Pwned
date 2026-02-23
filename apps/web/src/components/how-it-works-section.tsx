const STEPS = [
  {
    step: "01",
    title: "Connect your inventory",
    desc: "Share your extension list via our Chrome extension or API. No sensitive data leaves your machine - only extension IDs and metadata.",
  },
  {
    step: "02",
    title: "Automated risk analysis",
    desc: "We use a combination of static analysis, LLM agents and human expertise to identify problematic extensions.",
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
      <div className="grid gap-8 sm:grid-cols-3">
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
