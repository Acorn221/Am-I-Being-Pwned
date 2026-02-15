import {
  createContext,
  useCallback,
  useContext,
  useState,
  type ReactNode,
} from "react";

interface HeroCycleState {
  paused: boolean;
  pause: () => void;
  resume: () => void;
}

const HeroCycleContext = createContext<HeroCycleState>({
  paused: false,
  pause: () => {},
  resume: () => {},
});

export function HeroCycleProvider({ children }: { children: ReactNode }) {
  const [paused, setPaused] = useState(false);

  const pause = useCallback(() => setPaused(true), []);
  const resume = useCallback(() => setPaused(false), []);

  return (
    <HeroCycleContext.Provider value={{ paused, pause, resume }}>
      {children}
    </HeroCycleContext.Provider>
  );
}

export function useHeroCycle() {
  return useContext(HeroCycleContext);
}
