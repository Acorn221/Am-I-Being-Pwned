"use no memo";

import { useMemo, useRef } from "react";
import { animated } from "@react-spring/three";
import { Line } from "@react-three/drei";
import * as THREE from "three";

import {
  type PieceEdges,
  createPuzzlePieceGeometry,
} from "./puzzle-piece-geometry";
import {
  type RiskGroup,
  riskToGroup,
  useShatterAnimation,
} from "./use-shatter-animation";

const RISK_COLORS: Record<RiskGroup, string> = {
  safe: "#4ade80",
  warning: "#fbbf24",
  danger: "#f87171",
};

interface PuzzlePieceProps {
  edges: PieceEdges;
  risk: string;
  position: [number, number, number];
  isFocal?: boolean;
  reducedMotion: boolean;
}

export function PuzzlePiece({
  edges,
  risk,
  position,
  isFocal = false,
  reducedMotion,
}: PuzzlePieceProps) {
  const meshRef = useRef<THREE.Mesh>(null);
  const group = riskToGroup(risk);
  const color = RISK_COLORS[group];

  const geometry = useMemo(() => createPuzzlePieceGeometry(edges), [edges]);

  const { spring, crackLines } = useShatterAnimation(
    group,
    position,
    reducedMotion,
  );

  // Convert BufferGeometries to point arrays for drei's Line component
  const crackPoints = useMemo(
    () =>
      crackLines.map((geo) => {
        const pos = geo.getAttribute("position");
        const pts: [number, number, number][] = [];
        for (let i = 0; i < pos.count; i++) {
          pts.push([pos.getX(i), pos.getY(i), pos.getZ(i)]);
        }
        return pts;
      }),
    [crackLines],
  );

  return (
    <animated.group
      position={spring.position as unknown as THREE.Vector3}
      rotation={spring.rotation as unknown as THREE.Euler}
    >
      <mesh ref={meshRef} geometry={geometry}>
        <meshPhysicalMaterial
          color={color}
          transparent
          opacity={isFocal ? 0.75 : 0.55}
          roughness={isFocal ? 0.05 : 0.15}
          metalness={0.1}
          transmission={isFocal ? 0.9 : 0.7}
          thickness={isFocal ? 0.5 : 0.3}
          ior={1.5}
          envMapIntensity={isFocal ? 1.2 : 0.6}
          clearcoat={isFocal ? 1 : 0}
          clearcoatRoughness={0.1}
          emissive={group === "danger" ? color : "#000000"}
          emissiveIntensity={group === "danger" ? (isFocal ? 0.5 : 0.25) : 0}
          side={THREE.DoubleSide}
        />
      </mesh>

      {/* Crack lines on danger pieces */}
      {crackPoints.map((pts, i) => (
        <Line
          key={i}
          points={pts}
          color="#ff0000"
          lineWidth={1.5}
          transparent
          opacity={0.7}
        />
      ))}
    </animated.group>
  );
}
