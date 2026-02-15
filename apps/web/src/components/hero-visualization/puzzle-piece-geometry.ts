"use no memo";

import * as THREE from "three";

export type EdgeType = "tab" | "blank" | "flat";

export interface PieceEdges {
  top: EdgeType;
  right: EdgeType;
  bottom: EdgeType;
  left: EdgeType;
}

/** Simple hash from string to deterministic number 0-1 */
function hashSeed(id: string): number {
  let h = 0;
  for (let i = 0; i < id.length; i++) {
    h = (Math.imul(31, h) + id.charCodeAt(i)) | 0;
  }
  return ((h >>> 0) % 1000) / 1000;
}

/** Assign edges for a piece based on grid position and ID */
export function assignEdges(
  row: number,
  col: number,
  rows: number,
  cols: number,
  id: string,
): PieceEdges {
  const seed = hashSeed(id);
  const pick = (s: number): "tab" | "blank" =>
    s > 0.5 ? "tab" : "blank";

  return {
    top: row === 0 ? "flat" : pick(seed),
    right: col === cols - 1 ? "flat" : pick((seed * 7 + 0.3) % 1),
    bottom: row === rows - 1 ? "flat" : pick((seed * 13 + 0.6) % 1),
    left: col === 0 ? "flat" : pick((seed * 19 + 0.1) % 1),
  };
}

const PIECE_SIZE = 1;
const TAB_SIZE = 0.22;
const TAB_NECK = 0.12;

/**
 * Draw a tab (protruding knob) or blank (matching indentation)
 * along one edge direction. The cursor moves from start to end of that edge.
 */
function drawEdge(
  shape: THREE.Shape,
  edge: EdgeType,
  startX: number,
  startY: number,
  dirX: number,
  dirY: number,
) {
  // perpendicular direction (pointing outward from shape center)
  const perpX = -dirY;
  const perpY = dirX;

  const half = PIECE_SIZE / 2;
  const neckHalf = TAB_NECK / 2;
  const tabDepth = TAB_SIZE;

  if (edge === "flat") {
    shape.lineTo(startX + dirX * PIECE_SIZE, startY + dirY * PIECE_SIZE);
    return;
  }

  const sign = edge === "tab" ? 1 : -1;

  // Move to the neck start
  const neckStart = half - neckHalf;
  const neckEnd = half + neckHalf;

  shape.lineTo(
    startX + dirX * neckStart,
    startY + dirY * neckStart,
  );

  // Bezier curve for the tab/blank bulge
  const cp1x =
    startX + dirX * neckStart + perpX * sign * tabDepth * 0.6;
  const cp1y =
    startY + dirY * neckStart + perpY * sign * tabDepth * 0.6;
  const cp2x =
    startX + dirX * (half - neckHalf * 1.5) + perpX * sign * tabDepth;
  const cp2y =
    startY + dirY * (half - neckHalf * 1.5) + perpY * sign * tabDepth;
  const midX = startX + dirX * half + perpX * sign * tabDepth;
  const midY = startY + dirY * half + perpY * sign * tabDepth;

  shape.bezierCurveTo(cp1x, cp1y, cp2x, cp2y, midX, midY);

  const cp3x =
    startX + dirX * (half + neckHalf * 1.5) + perpX * sign * tabDepth;
  const cp3y =
    startY + dirY * (half + neckHalf * 1.5) + perpY * sign * tabDepth;
  const cp4x =
    startX + dirX * neckEnd + perpX * sign * tabDepth * 0.6;
  const cp4y =
    startY + dirY * neckEnd + perpY * sign * tabDepth * 0.6;
  const endNeckX = startX + dirX * neckEnd;
  const endNeckY = startY + dirY * neckEnd;

  shape.bezierCurveTo(cp3x, cp3y, cp4x, cp4y, endNeckX, endNeckY);

  // Continue to edge end
  shape.lineTo(startX + dirX * PIECE_SIZE, startY + dirY * PIECE_SIZE);
}

export function createPuzzlePieceGeometry(edges: PieceEdges): THREE.ExtrudeGeometry {
  const shape = new THREE.Shape();
  const hs = PIECE_SIZE / 2;

  // Start bottom-left
  shape.moveTo(-hs, -hs);

  // Bottom edge (left to right)
  drawEdge(shape, edges.bottom, -hs, -hs, 1, 0);

  // Right edge (bottom to top)
  drawEdge(shape, edges.right, hs, -hs, 0, 1);

  // Top edge (right to left)
  drawEdge(shape, edges.top, hs, hs, -1, 0);

  // Left edge (top to bottom)
  drawEdge(shape, edges.left, -hs, hs, 0, -1);

  const geometry = new THREE.ExtrudeGeometry(shape, {
    depth: 0.15,
    bevelEnabled: true,
    bevelThickness: 0.02,
    bevelSize: 0.02,
    bevelSegments: 3,
    curveSegments: 16,
  });

  geometry.center();
  geometry.computeVertexNormals();
  return geometry;
}
