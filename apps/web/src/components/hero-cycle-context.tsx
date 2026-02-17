import {
  createContext,
  useCallback,
  useContext,
  useState,
  type ReactNode,
} from "react";

import { HERO_SLIDES } from "~/components/hero-slides";

interface HeroCycleState {
  /** Current slide index into HERO_SLIDES */
  slideIndex: number;
  paused: boolean;
  pause: () => void;
  resume: () => void;
  advance: () => void;
}

const HeroCycleContext = createContext<HeroCycleState>({
  slideIndex: 0,
  paused: false,
  pause: () => {},
  resume: () => {},
  advance: () => {},
});

export function HeroCycleProvider({ children }: { children: ReactNode }) {
  const [paused, setPaused] = useState(false);
  const [slideIndex, setSlideIndex] = useState(0);

  const pause = useCallback(() => setPaused(true), []);
  const resume = useCallback(() => setPaused(false), []);
  const advance = useCallback(
    () => setSlideIndex((i) => (i + 1) % HERO_SLIDES.length),
    [],
  );

  return (
    <HeroCycleContext.Provider
      value={{ slideIndex, paused, pause, resume, advance }}
    >
      {children}
    </HeroCycleContext.Provider>
  );
}

export function useHeroCycle() {
  return useContext(HeroCycleContext);
}
