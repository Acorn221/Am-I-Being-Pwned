import { useEffect, useMemo, useRef, useState } from "react";

const PHRASES: string[] = [
  "ad blocker",
  "Chrome extension",
  "free VPN",
  "productivity app",
  "grammar checker",
  "coupon finder",
  "screenshot tool",
  "password manager",
  "PDF converter",
  "email tracker",
  "tab manager",
  "video downloader",
  "clipboard manager",
  "new tab page",
  "browser theme",
  "price tracker",
];

const TYPING_SPEED = 100;
const DELETING_SPEED = 100;
const PAUSE_AFTER_TYPED = 3000;
const PAUSE_AFTER_DELETED = 200;

export function TypingTitle() {
  const [displayText, setDisplayText] = useState("");
  // All mutable state in a single ref so tick() never reads stale closures
  const ref = useRef({
    phrase: 0,
    charIndex: 0,
    deleting: false,
  });
  const timeoutRef = useRef<ReturnType<typeof setTimeout>>(null);

  const longestPhrase = useMemo(
    () => PHRASES.reduce((a, b) => (a.length >= b.length ? a : b), ""),
    [],
  );

  useEffect(() => {
    function tick() {
      const s = ref.current;
      // eslint-disable-next-line @typescript-eslint/no-non-null-assertion
      const fullText = PHRASES[s.phrase] ?? PHRASES[0]!;

      if (!s.deleting) {
        // Typing forward
        s.charIndex++;
        const text = fullText.slice(0, s.charIndex);
        setDisplayText(text);

        if (s.charIndex >= fullText.length) {
          // Finished typing — pause, then start deleting
          timeoutRef.current = setTimeout(() => {
            s.deleting = true;
            tick();
          }, PAUSE_AFTER_TYPED);
        } else {
          timeoutRef.current = setTimeout(tick, TYPING_SPEED);
        }
      } else {
        // Deleting backward
        s.charIndex--;
        const text = fullText.slice(0, s.charIndex);
        setDisplayText(text);

        if (s.charIndex <= 0) {
          // Finished deleting — switch phrase, then start typing
          s.deleting = false;
          s.charIndex = 0;
          s.phrase = (s.phrase + 1) % PHRASES.length;
          timeoutRef.current = setTimeout(tick, PAUSE_AFTER_DELETED);
        } else {
          timeoutRef.current = setTimeout(tick, DELETING_SPEED);
        }
      }
    }

    timeoutRef.current = setTimeout(tick, PAUSE_AFTER_DELETED);
    return () => {
      if (timeoutRef.current) clearTimeout(timeoutRef.current);
    };
  }, []);

  return (
    <h1 className="text-foreground mb-4 text-4xl font-bold tracking-tight sm:text-5xl">
      Is my{" "}
      <span className="inline-grid align-baseline">
        <span className="text-primary col-start-1 row-start-1">
          {displayText}
          <span
            className="bg-primary ml-px inline-block h-[1.1em] w-0.5 translate-y-[0.15em] animate-pulse"
            aria-hidden
          />
        </span>
        <span className="invisible col-start-1 row-start-1" aria-hidden>
          {longestPhrase}
        </span>
      </span>
      <br />
      spying on me?
    </h1>
  );
}
