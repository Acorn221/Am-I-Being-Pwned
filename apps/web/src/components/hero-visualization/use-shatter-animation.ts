"use no memo";

import { useEffect, useMemo } from "react";
import { useSpring } from "@react-spring/three";
import * as THREE from "three";

export type RiskGroup = "safe" | "warning" | "danger";

export function riskToGroup(risk: string): RiskGroup {
  switch (risk) {
    case "critical":
    case "high":
      return "danger";
    case "medium-high":
    case "medium":
      return "warning";
    default:
      return "safe";
  }
}

interface ShatterResult {
  // eslint-disable-next-line @typescript-eslint/no-explicit-any
  spring: any;
  crackLines: THREE.BufferGeometry[];
}

export function useShatterAnimation(
  group: RiskGroup,
  basePosition: [number, number, number],
  reducedMotion: boolean,
): ShatterResult {
  const [spring] = useSpring(() => {
    if (reducedMotion || group !== "danger") {
      return {
        position: basePosition,
        rotation: [0, 0, 0] as [number, number, number],
        emissiveIntensity: group === "danger" ? 0.4 : 0,
        config: { tension: 120, friction: 14 },
      };
    }

    return {
      from: {
        position: basePosition,
        rotation: [0, 0, 0] as [number, number, number],
        emissiveIntensity: 0,
      },
      to: async (next: (props: Record<string, unknown>) => Promise<void>) => {
        // Wait for scene to settle
        await new Promise((r) => setTimeout(r, 1200));

        // Shudder
        const shudder = 0.04;
        for (let i = 0; i < 4; i++) {
          await next({
            position: [
              basePosition[0] + (Math.random() - 0.5) * shudder,
              basePosition[1] + (Math.random() - 0.5) * shudder,
              basePosition[2],
            ],
            config: { tension: 600, friction: 10 },
          });
        }

        // Drift out
        const angle = Math.atan2(basePosition[1], basePosition[0]);
        await next({
          position: [
            basePosition[0] + Math.cos(angle) * 0.6,
            basePosition[1] + Math.sin(angle) * 0.6,
            basePosition[2] + 0.3,
          ],
          rotation: [
            (Math.random() - 0.5) * 0.3,
            (Math.random() - 0.5) * 0.3,
            (Math.random() - 0.5) * 0.2,
          ],
          emissiveIntensity: 0.6,
          config: { tension: 40, friction: 12 },
        });
      },
    };
  }, [group, reducedMotion]);

  // Crack geometry is intentionally randomised once per group change.
  // "use no memo" opts this file out of the React Compiler so these random
  // values are stable across re-renders (memoised by useMemo).
  /* eslint-disable react-hooks/purity */
  const crackLines = useMemo(() => {
    if (group !== "danger") return [];

    const lines: THREE.BufferGeometry[] = [];
    const count = 2 + Math.floor(Math.random() * 2);

    for (let i = 0; i < count; i++) {
      const points: THREE.Vector3[] = [];
      const segments = 4 + Math.floor(Math.random() * 3);
      let x = (Math.random() - 0.5) * 0.6;
      let y = (Math.random() - 0.5) * 0.6;

      for (let s = 0; s < segments; s++) {
        points.push(new THREE.Vector3(x, y, 0.08));
        x += (Math.random() - 0.5) * 0.25;
        y += (Math.random() - 0.5) * 0.25;
      }

      const geo = new THREE.BufferGeometry().setFromPoints(points);
      lines.push(geo);
    }

    return lines;
  }, [group]);
  /* eslint-enable react-hooks/purity */

  // Cleanup geometries
  useEffect(() => {
    return () => {
      crackLines.forEach((g) => g.dispose());
    };
  }, [crackLines]);

  return { spring, crackLines };
}
