import { useCallback, useEffect, useRef, useState } from "react";
import { ChevronLeft, ChevronRight, Eye, Globe, ShieldAlert, Syringe, Wifi } from "lucide-react";

const THREATS = [
  {
    icon: Eye,
    title: "Data Harvesting",
    desc: "Extensions silently collect browsing history, keystrokes, form inputs, and personal data - then upload it to remote servers. Often disguised as productivity tools or ad blockers, these extensions can build detailed profiles of every employee in your organisation without anyone noticing.",
  },
  {
    icon: Globe,
    title: "Session Hijacking",
    desc: "By reading authentication tokens and cookies, malicious extensions can impersonate your employees on any website - including internal tools, SaaS platforms, and corporate email. The attacker never needs a password.",
  },
  {
    icon: Syringe,
    title: "Code Injection",
    desc: "Extensions with broad host permissions can inject arbitrary JavaScript into any page your employees visit. This enables ad injection, UI manipulation, credential skimming, and modification of internal web apps.",
  },
  {
    icon: Wifi,
    title: "Network Tampering",
    desc: "Some extensions intercept and modify network requests in real time - proxying traffic through attacker-controlled servers, injecting malware into responses, or routing your employees' connections through residential botnet nodes.",
  },
  {
    icon: ShieldAlert,
    title: "Vulnerability Discovery",
    desc: "Many extensions are built with little regard for security and are vulnerable to attacks, we have already identified over 4 vulnerabilities in popular extensions with CVSS scores between 8 and 9.6",
  },
  {
    icon: ShieldAlert,
    title: "Known Vulnerabilities",
    desc: "Beyond malicious intent, many extensions have poor security hygiene: outdated dependencies with known CVEs, insecure data storage, and un-validated remote code execution paths. Any of these can be exploited by a third party.",
  },
] as const;

const INTERVAL_MS = 5000;
const SLIDE_DURATION = 350;

export function ThreatCarousel() {
  const [active, setActive] = useState(0);
  const [prevIndex, setPrevIndex] = useState<number | null>(null);
  const [direction, setDirection] = useState<"forward" | "back">("forward");
  const [paused, setPaused] = useState(false);
  const touchStartX = useRef<number | null>(null);

  const goTo = useCallback(
    (index: number) => {
      if (prevIndex !== null || index === active) return;
      const n = THREATS.length;
      const diff = (index - active + n) % n;
      const dir: "forward" | "back" = diff <= n / 2 ? "forward" : "back";
      setDirection(dir);
      setPrevIndex(active);
      setActive(index);
      setTimeout(() => setPrevIndex(null), SLIDE_DURATION);
    },
    [active, prevIndex],
  );

  useEffect(() => {
    if (paused) return;
    const id = setInterval(() => {
      goTo((active + 1) % THREATS.length);
    }, INTERVAL_MS);
    return () => clearInterval(id);
  }, [paused, active, goTo]);

  const threat = THREATS[active];
  if (!threat) return null;

  function prev() {
    goTo((active - 1 + THREATS.length) % THREATS.length);
    setPaused(true);
  }

  function next() {
    goTo((active + 1) % THREATS.length);
    setPaused(true);
  }

  return (
    <div
      className="flex gap-8"
      style={{ touchAction: "pan-y" }}
      onMouseEnter={() => setPaused(true)}
      onMouseLeave={() => setPaused(false)}
      onTouchStart={(e) => { touchStartX.current = e.touches[0]?.clientX ?? null; }}
      onTouchEnd={(e) => {
        if (touchStartX.current === null) return;
        const dx = (e.changedTouches[0]?.clientX ?? 0) - touchStartX.current;
        touchStartX.current = null;
        if (Math.abs(dx) < 40) return;
        if (dx < 0) next(); else prev();
      }}
    >
      {/* Sidebar nav - desktop */}
      <div
        className="hidden flex-col gap-1 sm:flex"
        style={{ minWidth: "11rem" }}
      >
        {THREATS.map((t, i) => (
          <button
            key={t.title}
            onClick={() => {
              goTo(i);
              setPaused(true);
            }}
            className={`rounded-md px-3 py-2 text-left text-sm transition-colors ${
              i === active
                ? "bg-accent text-foreground font-medium"
                : "text-muted-foreground hover:text-foreground"
            }`}
          >
            {t.title}
          </button>
        ))}
      </div>

      {/* Card */}
      <div className="flex-1">
        <style>{`
          @keyframes slide-in-right  { from { transform: translateX(100%); } to { transform: translateX(0); } }
          @keyframes slide-out-left  { from { transform: translateX(0); }    to { transform: translateX(-100%); } }
          @keyframes slide-in-left   { from { transform: translateX(-100%); } to { transform: translateX(0); } }
          @keyframes slide-out-right { from { transform: translateX(0); }    to { transform: translateX(100%); } }
        `}</style>
        <div className="relative h-[22rem] overflow-hidden rounded-xl sm:h-64">
          {/* Outgoing card */}
          {prevIndex !== null &&
            (() => {
              const prev = THREATS[prevIndex];
              if (!prev) return null;
              return (
                <div
                  className="border-border bg-card absolute inset-0 rounded-xl border p-6 sm:p-8"
                  style={{
                    animation: `${direction === "forward" ? "slide-out-left" : "slide-out-right"} ${SLIDE_DURATION}ms ease forwards`,
                  }}
                >
                  <prev.icon className="text-primary mb-5 h-7 w-7" />
                  <h3 className="text-foreground mb-3 text-xl font-semibold">
                    {prev.title}
                  </h3>
                  <p className="text-muted-foreground leading-relaxed">
                    {prev.desc}
                  </p>
                </div>
              );
            })()}

          {/* Incoming card */}
          <div
            className="border-border bg-card absolute inset-0 rounded-xl border p-6 sm:p-8"
            style={
              prevIndex !== null
                ? {
                    animation: `${direction === "forward" ? "slide-in-right" : "slide-in-left"} ${SLIDE_DURATION}ms ease forwards`,
                  }
                : {}
            }
          >
            <threat.icon className="text-primary mb-5 h-7 w-7" />
            <h3 className="text-foreground mb-3 text-xl font-semibold">
              {threat.title}
            </h3>
            <p className="text-muted-foreground leading-relaxed">
              {threat.desc}
            </p>
          </div>
        </div>

        {/* Mobile nav */}
        <div className="mt-4 flex items-center gap-3 sm:hidden">
          <button
            onClick={prev}
            className="text-muted-foreground hover:text-foreground"
          >
            <ChevronLeft className="h-4 w-4" />
          </button>
          <div className="flex flex-1 justify-center gap-1.5">
            {THREATS.map((_, i) => (
              <button
                key={i}
                onClick={() => {
                  goTo(i);
                  setPaused(true);
                }}
                className="flex items-center py-2"
              >
                <span
                  className={`block h-1.5 rounded-full transition-all duration-300 ${
                    i === active ? "bg-primary w-12" : "bg-border w-6"
                  }`}
                />
              </button>
            ))}
          </div>
          <button
            onClick={next}
            className="text-muted-foreground hover:text-foreground"
          >
            <ChevronRight className="h-4 w-4" />
          </button>
        </div>

        {/* Progress dots - desktop */}
        <div className="mt-4 hidden gap-1.5 sm:flex">
          {THREATS.map((_, i) => (
            <button
              key={i}
              onClick={() => {
                goTo(i);
                setPaused(true);
              }}
              className="flex items-center py-2"
            >
              <span
                className={`block h-1.5 rounded-full transition-all duration-300 ${
                  i === active ? "bg-primary w-12" : "bg-border w-6"
                }`}
              />
            </button>
          ))}
        </div>
      </div>
    </div>
  );
}
