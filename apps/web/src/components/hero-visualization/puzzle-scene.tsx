"use no memo";

import { useMemo } from "react";
import { Canvas } from "@react-three/fiber";
import { Float } from "@react-three/drei";

import type { RiskLevel } from "@amibeingpwned/types";

import { riskOrder } from "~/lib/risk";

import {  assignEdges } from "./puzzle-piece-geometry";
import type {PieceEdges} from "./puzzle-piece-geometry";
import { PuzzlePiece } from "./puzzle-piece";

interface PieceData {
  id: string;
  name: string;
  risk: RiskLevel;
  edges: PieceEdges;
  position: [number, number, number];
  row: number;
  col: number;
  isFocal: boolean;
}

interface PuzzleSceneProps {
  pieces: { id: string; name: string; risk: RiskLevel }[];
  reducedMotion: boolean;
}

const MAX_PIECES = 12;
const COLS = 4;
const SPACING = 1.15;

export function PuzzleScene({ pieces, reducedMotion }: PuzzleSceneProps) {
  const pieceData = useMemo(() => {
    // Sort: danger first, then safe - show most interesting pieces
    const sorted = [...pieces]
      .sort((a, b) => riskOrder[a.risk] - riskOrder[b.risk])
      .slice(0, MAX_PIECES);

    const rows = Math.ceil(sorted.length / COLS);
    const totalWidth = (COLS - 1) * SPACING;
    const totalHeight = (rows - 1) * SPACING;

    return sorted.map((piece, i): PieceData => {
      const row = Math.floor(i / COLS);
      const col = i % COLS;

      return {
        ...piece,
        edges: assignEdges(row, col, rows, COLS, piece.id),
        position: [
          col * SPACING - totalWidth / 2,
          -(row * SPACING - totalHeight / 2),
          0,
        ],
        row,
        col,
        isFocal:
          piece.risk === "critical" ||
          piece.risk === "high" ||
          piece.risk === "medium-high",
      };
    });
  }, [pieces]);

  return (
    <Canvas
      dpr={[1, 1.5]}
      camera={{ position: [0, 0, 6], fov: 35 }}
      style={{ background: "transparent" }}
      gl={{ alpha: true, powerPreference: "default", antialias: true }}
    >
      <ambientLight intensity={0.5} />
      <directionalLight position={[5, 5, 5]} intensity={1} />
      <directionalLight position={[-3, -2, 4]} intensity={0.4} />
      <pointLight position={[0, 0, 4]} intensity={0.6} color="#ffffff" />

      <Float
        speed={reducedMotion ? 0 : 1.5}
        rotationIntensity={reducedMotion ? 0 : 0.15}
        floatIntensity={reducedMotion ? 0 : 0.3}
      >
        <group>
          {pieceData.map((piece) => (
            <PuzzlePiece
              key={piece.id}
              edges={piece.edges}
              risk={piece.risk}
              position={piece.position}
              isFocal={piece.isFocal}
              reducedMotion={reducedMotion}
            />
          ))}
        </group>
      </Float>
    </Canvas>
  );
}
