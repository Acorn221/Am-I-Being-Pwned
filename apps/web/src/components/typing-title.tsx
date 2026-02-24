import { useEffect, useMemo, useRef, useState } from "react";

import { useHeroCycle } from "~/components/hero-cycle-context";
import { HERO_SLIDES } from "~/components/hero-slides";

const TYPING_SPEED = 120;
const DELETING_SPEED = 60;
const PAUSE_AFTER_TYPED_BASE = 4000;
const PAUSE_PER_ANNOTATION = 1000;
const PAUSE_AFTER_DELETED = 400;

export function TypingTitle() {
  const { slideIndex, paused, advance } = useHeroCycle();
  const [displayText, setDisplayText] = useState("");
  const state = useRef({
    charIndex: 0,
    deleting: false,
  });
  const timeoutRef = useRef<ReturnType<typeof setTimeout>>(null);
  const pausedRef = useRef(paused);
  const slideRef = useRef(slideIndex);

  useEffect(() => {
    pausedRef.current = paused;
  }, [paused]);

  useEffect(() => {
    // eslint-disable-next-line @typescript-eslint/no-unsafe-assignment
    slideRef.current = slideIndex;
  }, [slideIndex]);

  const longestPhrase = useMemo(
    () =>
      HERO_SLIDES.reduce((a, b) => (a.phrase.length >= b.phrase.length ? a : b))
        .phrase,
    [],
  );

  useEffect(() => {
    function tick() {
      const s = state.current;
      // eslint-disable-next-line @typescript-eslint/no-unsafe-member-access
      const slide = HERO_SLIDES[slideRef.current];
      if (!slide) return;
      const fullText = slide.phrase;

      if (!s.deleting) {
        s.charIndex++;
        setDisplayText(fullText.slice(0, s.charIndex));

        if (s.charIndex >= fullText.length) {
          // Finished typing - wait, then delete (or hold if paused)
          const annotationCount = slide.annotations?.length ?? 0;
          const pauseTime =
            PAUSE_AFTER_TYPED_BASE + annotationCount * PAUSE_PER_ANNOTATION;
          timeoutRef.current = setTimeout(() => {
            if (pausedRef.current) {
              waitForResume();
            } else {
              s.deleting = true;
              tick();
            }
          }, pauseTime);
        } else {
          timeoutRef.current = setTimeout(tick, TYPING_SPEED);
        }
      } else {
        s.charIndex--;
        setDisplayText(fullText.slice(0, s.charIndex));

        if (s.charIndex <= 0) {
          // Finished deleting - advance to next slide, then start typing
          s.deleting = false;
          s.charIndex = 0;
          // eslint-disable-next-line @typescript-eslint/no-unsafe-call
          advance();
          timeoutRef.current = setTimeout(tick, PAUSE_AFTER_DELETED);
        } else {
          timeoutRef.current = setTimeout(tick, DELETING_SPEED);
        }
      }
    }

    function waitForResume() {
      if (!pausedRef.current) {
        tick();
        return;
      }
      timeoutRef.current = setTimeout(waitForResume, 100);
    }

    timeoutRef.current = setTimeout(tick, PAUSE_AFTER_DELETED);
    return () => {
      if (timeoutRef.current) clearTimeout(timeoutRef.current);
    };
  }, []); // eslint-disable-line react-hooks/exhaustive-deps

  return (
    <h1 className="text-foreground mb-4 text-4xl font-bold tracking-tight sm:text-5xl">
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
      are leaking company data.
    </h1>
  );
}
