import { useCallback, useEffect, useRef, useState } from "react";

const TESTIMONIALS = [
  {
    quote:
      "As a YC company handling streamer data, we needed to show investors and clients we take security seriously. Am I Being Pwned flagged extensions we'd never have caught manually, we cut our attack surface before it became a problem.",
    name: "Nang Ang",
    role: "Co-Founder, PearAI / Streamable",
    badge: "YC F24",
    avatar: "/imgs/nang.png",
    badgeIcon: "/imgs/yc_icon.svg",
  },
  {
    quote:
      "I was shocked to find out that my productivity extension had been spying on me, every website I visited was sent to some random server. Am I Being Pwned saved us from major potential issues by catching this.",
    name: "Kip Parker",
    role: "Co-Founder of General Reasoning",
    // badge: "YC F24",
    // avatar: "/imgs/nang.png", // TODO
    // badgeIcon: "/imgs/yc_icon.svg",
  },
  // {
  // quote:
  // "I ",
  // name: "Chris Mjelde",
  // role: "Co-Founder of Kenobi.ai",
  // badge: "YC W22",
  // avatar: "/imgs/nang.png", // TODO
  // badgeIcon: "/imgs/yc_icon.svg",
  // },
  // {
  // quote:
  // "I ",
  // name: "Rory McMeekin",
  // role: "Co-Founder of Kenobi.ai",
  // badge: "YC W22",
  // avatar: "/imgs/nang.png", // TODO
  // badgeIcon: "/imgs/yc_icon.svg",
  // },
];

const INTERVAL_MS = 6000;
const SLIDE_DURATION = 350;

export function TestimonialsSection() {
  const [active, setActive] = useState(0);
  const [prevIndex, setPrevIndex] = useState<number | null>(null);
  const [direction, setDirection] = useState<"forward" | "back">("forward");
  const [paused, setPaused] = useState(false);
  const touchStartX = useRef<number | null>(null);

  const goTo = useCallback(
    (index: number) => {
      if (prevIndex !== null || index === active) return;
      const n = TESTIMONIALS.length;
      const diff = (index - active + n) % n;
      setDirection(diff <= n / 2 ? "forward" : "back");
      setPrevIndex(active);
      setActive(index);
      setTimeout(() => setPrevIndex(null), SLIDE_DURATION);
    },
    [active, prevIndex],
  );

  useEffect(() => {
    if (paused || TESTIMONIALS.length <= 1) return;
    const id = setInterval(() => {
      goTo((active + 1) % TESTIMONIALS.length);
    }, INTERVAL_MS);
    return () => clearInterval(id);
  }, [paused, active, goTo]);

  const current = TESTIMONIALS[active];
  if (!current) return null;

  return (
    <section className="border-border/50 border-b">
      <style>{`
        @keyframes t-slide-in-right  { from { transform: translateX(100%); opacity: 0; } to { transform: translateX(0); opacity: 1; } }
        @keyframes t-slide-out-left  { from { transform: translateX(0); opacity: 1; } to { transform: translateX(-100%); opacity: 0; } }
        @keyframes t-slide-in-left   { from { transform: translateX(-100%); opacity: 0; } to { transform: translateX(0); opacity: 1; } }
        @keyframes t-slide-out-right { from { transform: translateX(0); opacity: 1; } to { transform: translateX(100%); opacity: 0; } }
      `}</style>
      <div className="mx-auto max-w-6xl px-6 py-16">
        <h2 className="text-foreground mb-10 text-xl font-semibold">
          What people are saying
        </h2>

        <div
          className="relative"
          onMouseEnter={() => setPaused(true)}
          onMouseLeave={() => setPaused(false)}
          onTouchStart={(e) => {
            touchStartX.current = e.touches[0]?.clientX ?? null;
          }}
          onTouchEnd={(e) => {
            if (touchStartX.current === null) return;
            const dx =
              (e.changedTouches[0]?.clientX ?? 0) - touchStartX.current;
            touchStartX.current = null;
            if (Math.abs(dx) < 40) return;
            if (dx < 0) goTo((active + 1) % TESTIMONIALS.length);
            else goTo((active - 1 + TESTIMONIALS.length) % TESTIMONIALS.length);
          }}
        >
          <div className="overflow-hidden">
            <div className="relative" style={{ minHeight: "11rem" }}>
              {/* Outgoing card */}
              {prevIndex !== null &&
                (() => {
                  const prev = TESTIMONIALS[prevIndex];
                  if (!prev) return null;
                  return (
                    <TestimonialCard
                      {...prev}
                      style={{
                        position: "absolute",
                        inset: 0,
                        animation: `${direction === "forward" ? "t-slide-out-left" : "t-slide-out-right"} ${SLIDE_DURATION}ms ease forwards`,
                      }}
                    />
                  );
                })()}
              {/* Incoming card */}
              <TestimonialCard
                {...current}
                style={
                  prevIndex !== null
                    ? {
                        position: "absolute",
                        inset: 0,
                        animation: `${direction === "forward" ? "t-slide-in-right" : "t-slide-in-left"} ${SLIDE_DURATION}ms ease forwards`,
                      }
                    : {}
                }
              />
            </div>
          </div>

          {/* Dots — only shown when there's more than one */}
          {TESTIMONIALS.length > 1 && (
            <div className="mt-6 flex gap-1.5">
              {TESTIMONIALS.map((_, i) => (
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
          )}
        </div>
      </div>
    </section>
  );
}

function TestimonialCard({
  quote,
  name,
  role,
  badge,
  avatar,
  badgeIcon,
  style,
}: (typeof TESTIMONIALS)[number] & { style?: React.CSSProperties }) {
  return (
    <div className="w-full sm:max-w-xl" style={style}>
      <div
        className="rounded-xl p-0.5"
        style={{ background: "linear-gradient(135deg, #FF6600, #FF9A3C)" }}
      >
        <figure className="bg-card flex h-full flex-col rounded-[11px] p-8">
          <blockquote className="text-foreground mb-6 flex-1 text-base leading-relaxed">
            &ldquo;{quote}&rdquo;
          </blockquote>
          <div
            className="mb-6 h-px w-full"
            style={{ background: "linear-gradient(90deg, #FF6600, #FF9A3C)" }}
          />
          <figcaption className="flex items-center gap-4">
            {avatar && (
              <img
                src={avatar}
                alt={name}
                className="h-12 w-12 rounded-full object-cover"
              />
            )}
            <div className="min-w-0 flex-1">
              <p className="text-foreground font-medium">{name}</p>
              <p className="text-muted-foreground truncate text-sm">{role}</p>
            </div>
            {badgeIcon && badge && (
              <div className="flex shrink-0 items-center gap-1.5">
                <img src={badgeIcon} alt="YC" className="h-5 w-5" />
                <span className="text-muted-foreground text-sm">{badge}</span>
              </div>
            )}
          </figcaption>
        </figure>
      </div>
    </div>
  );
}
