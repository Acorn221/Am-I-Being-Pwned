/* eslint-disable @typescript-eslint/no-non-null-assertion */
import type { PermAnnotation } from "~/components/hero-slides";

/** Set to true to render debug bounding boxes for traces/labels/chips */
export const SHOW_DEBUG_BOXES = false;

// ── Label slots scattered around the card ───────────────────────────────────
// Container: 480×440, card: ~x:70..420, y:22..402 (after front card rotation).
// labelX/labelY = foreignObject top-left. Anchor point is computed dynamically.
export const LABEL_WIDTH = 190;
export const LABEL_HEIGHT = 48;
export const LABEL_SLOTS = [
  { labelX: 420, labelY: 100 },
  { labelX: 420, labelY: 350 },
  { labelX: 280, labelY: -50 },
];

// ── Types ───────────────────────────────────────────────────────────────────
export interface DebugBox {
  x: number;
  y: number;
  w: number;
  h: number;
  color: string;
  label?: string;
  /** Rotation in degrees, around the box center */
  rotate?: number;
}

export interface TraceData {
  annotation: PermAnnotation;
  chipX: number;
  chipY: number;
  anchorX: number;
  anchorY: number;
  labelX: number;
  labelY: number;
  path: string;
  pathLength: number;
}

// ── Geometry helpers ────────────────────────────────────────────────────────

const CORNER_INSET = 4;

/** Pick the nearest corner of a box to a target point (inset by CORNER_INSET). */
export function bestCorner(
  box: { x: number; y: number; w: number; h: number },
  targetX: number,
  targetY: number,
): { x: number; y: number } {
  const corners: [number, number][] = [
    [box.x + CORNER_INSET, box.y + CORNER_INSET],
    [box.x + box.w - CORNER_INSET, box.y + CORNER_INSET],
    [box.x + CORNER_INSET, box.y + box.h - CORNER_INSET],
    [box.x + box.w - CORNER_INSET, box.y + box.h - CORNER_INSET],
  ];

  let best: [number, number] = corners[0]!;
  let bestDist = Infinity;

  for (const [cx, cy] of corners) {
    const dx = cx - targetX;
    const dy = cy - targetY;
    const dist = dx * dx + dy * dy;
    if (dist < bestDist) {
      bestDist = dist;
      best = [cx, cy];
    }
  }

  return { x: best[0], y: best[1] };
}

/** Build an SVG path string from pixel points and return its length. */
export function pointsToSvg(points: [number, number][]): {
  path: string;
  length: number;
} {
  let path = `M ${points[0]![0]} ${points[0]![1]}`;
  let length = 0;

  for (let i = 1; i < points.length; i++) {
    const [x, y] = points[i]!;
    const [px, py] = points[i - 1]!;
    path += ` L ${x} ${y}`;
    length += Math.sqrt((x - px) ** 2 + (y - py) ** 2);
  }

  return { path, length: Math.ceil(length) };
}

// ── Deterministic polyline routing ──────────────────────────────────────────
// Always exit the card to the RIGHT, then route outside the card to the label.
// This guarantees no crossing of card text content.
//
// Route structure:
//   1. Chip right-center → card exit (horizontal)
//   2. Card exit → toward label (45° diagonal covering the shorter axis)
//   3. Remaining distance (horizontal or vertical straight)
//
// For labels LEFT of the card exit (slot 2 above the card):
//   2. Card exit → up/down to label Y (vertical along the right edge)
//   3. Then horizontal left to label

export const CARD_EXIT_MARGIN = 12; // px past the card's right edge
export const EXIT_STAGGER = 16; // px between each trace's exit column
export const LABEL_AVOID_PAD = 8; // px padding around labels for avoidance

/** Check if a line segment (p1→p2) intersects an axis-aligned rectangle. */
export function segmentHitsBox(
  p1x: number,
  p1y: number,
  p2x: number,
  p2y: number,
  box: { x: number; y: number; w: number; h: number },
  pad: number,
): boolean {
  const bx = box.x - pad;
  const by = box.y - pad;
  const bw = box.w + pad * 2;
  const bh = box.h + pad * 2;

  // Check multiple sample points along the segment
  const steps = Math.max(
    8,
    Math.ceil(Math.sqrt((p2x - p1x) ** 2 + (p2y - p1y) ** 2) / 4),
  );
  for (let s = 0; s <= steps; s++) {
    const t = s / steps;
    const px = p1x + (p2x - p1x) * t;
    const py = p1y + (p2y - p1y) * t;
    if (px >= bx && px <= bx + bw && py >= by && py <= by + bh) return true;
  }
  return false;
}

/**
 * Check if segments (from startSeg onward) in a polyline hit any obstacle.
 * startSeg=1 skips the first segment (chip → exit column) which is inside the card.
 */
export function routeHitsObstacles(
  points: [number, number][],
  obstacles: { x: number; y: number; w: number; h: number }[],
  startSeg = 0,
): boolean {
  for (let i = startSeg; i < points.length - 1; i++) {
    const [x1, y1] = points[i]!;
    const [x2, y2] = points[i + 1]!;
    for (const ob of obstacles) {
      if (segmentHitsBox(x1, y1, x2, y2, ob, LABEL_AVOID_PAD)) return true;
    }
  }
  return false;
}

/**
 * Route from chip to label anchor in two phases:
 *   Phase 1: Exit the chip zone - short segment from chip to a clear point
 *            outside the chip bounding box (not checked against chip obstacles).
 *   Phase 2: Route from the clear point to the label anchor, avoiding all
 *            text + label obstacles.
 */
export function buildRoute(
  chipRect: { x: number; y: number; w: number; h: number },
  labelAnchor: { x: number; y: number },
  exitX: number,
  textObstacles: { x: number; y: number; w: number; h: number }[],
  chipZone: { x: number; y: number; w: number; h: number } | null,
  quiet = false,
): [number, number][] {
  // Try all 4 chip corners - pick the one with the shortest obstacle-free route.
  const chipCorners: [number, number][] = [
    [chipRect.x + CORNER_INSET, chipRect.y + CORNER_INSET],
    [chipRect.x + chipRect.w - CORNER_INSET, chipRect.y + CORNER_INSET],
    [chipRect.x + CORNER_INSET, chipRect.y + chipRect.h - CORNER_INSET],
    [
      chipRect.x + chipRect.w - CORNER_INSET,
      chipRect.y + chipRect.h - CORNER_INSET,
    ],
  ];

  const results: {
    route: [number, number][];
    len: number;
    corner: number;
    strategy: string;
  }[] = [];

  const fmt = (pts: [number, number][]) =>
    pts.map((p) => `(${Math.round(p[0])},${Math.round(p[1])})`).join("→");

  /** Check which obstacles a route hits (for logging). */
  const findHits = (pts: [number, number][], skip: number) => {
    const hits: string[] = [];
    for (let i = skip; i < pts.length - 1; i++) {
      const [x1, y1] = pts[i]!;
      const [x2, y2] = pts[i + 1]!;
      for (const ob of allObstacles) {
        if (segmentHitsBox(x1, y1, x2, y2, ob, LABEL_AVOID_PAD)) {
          const isChipZone = chipZone && ob === chipZone;
          hits.push(
            `seg${i}(${Math.round(x1)},${Math.round(y1)}→${Math.round(x2)},${Math.round(y2)}) hits ${isChipZone ? "CHIPZONE" : "box"}(${Math.round(ob.x)},${Math.round(ob.y)} ${Math.round(ob.w)}×${Math.round(ob.h)})`,
          );
        }
      }
    }
    return hits;
  };

  // Include chip zone as an obstacle so routes don't cut through the chip row
  const allObstacles = chipZone ? [...textObstacles, chipZone] : textObstacles;

  for (let ci = 0; ci < chipCorners.length; ci++) {
    const [sx, sy] = chipCorners[ci]!;
    const ep: [number, number] = chipZone
      ? [chipZone.x + chipZone.w + 4, sy]
      : [exitX, sy];

    const clear = (pts: [number, number][], skip: number): boolean =>
      !routeHitsObstacles(pts, allObstacles, skip);

    const target: [number, number] = [labelAnchor.x, labelAnchor.y];

    // 1. Direct: chip → anchor (check all segments)
    const d: [number, number][] = [[sx, sy], target];
    if (clear(d, 0)) {
      results.push({
        route: d,
        len: pathLength(d),
        corner: ci,
        strategy: "direct",
      });
      continue;
    }
    // if (!quiet)
    // console.log(`  [corner${ci}] direct BLOCKED: ${fmt(d)}`, findHits(d, 0));

    // 2. Exit → anchor (skip chip→exit)
    const r1: [number, number][] = [[sx, sy], ep, target];
    if (clear(r1, 1)) {
      results.push({
        route: r1,
        len: pathLength(r1),
        corner: ci,
        strategy: "exit→anchor",
      });
      continue;
    }
    // if (!quiet)
    // console.log(
    //   `  [corner${ci}] exit→anchor BLOCKED: ${fmt(r1)}`,
    //   findHits(r1, 1),
    // );

    // 3. Exit → exit column → anchor
    const r2: [number, number][] = [[sx, sy], ep, [exitX, ep[1]], target];
    if (clear(r2, 1)) {
      results.push({
        route: r2,
        len: pathLength(r2),
        corner: ci,
        strategy: "exit→col→anchor",
      });
      continue;
    }
    // if (!quiet)
    // console.log(
    //   `  [corner${ci}] exit→col→anchor BLOCKED: ${fmt(r2)}`,
    //   findHits(r2, 1),
    // );

    // 4. Vertical detour scan
    const step = labelAnchor.y < ep[1] ? -6 : 6;
    let found = false;
    for (
      let clearY = ep[1] + step;
      Math.abs(clearY - ep[1]) < 400;
      clearY += step
    ) {
      const r3: [number, number][] = [[sx, sy], ep, [exitX, clearY], target];
      if (clear(r3, 1)) {
        results.push({
          route: r3,
          len: pathLength(r3),
          corner: ci,
          strategy: `detour@y=${Math.round(clearY)}`,
        });
        found = true;
        break;
      }
    }
    if (found) continue;

    // 5. Wide fallback
    const wideX = Math.max(
      exitX + 20,
      ...textObstacles.map((o) => o.x + o.w + LABEL_AVOID_PAD + 8),
    );
    for (let clearY = ep[1]; Math.abs(clearY - ep[1]) < 400; clearY += step) {
      const r4: [number, number][] = [[sx, sy], ep, [wideX, clearY], target];
      if (clear(r4, 1)) {
        results.push({
          route: r4,
          len: pathLength(r4),
          corner: ci,
          strategy: `wide@(${Math.round(wideX)},${Math.round(clearY)})`,
        });
        found = true;
        break;
      }
    }

    // if (!found && !quiet) {
    // } // console.log(`  [corner${ci}] ALL strategies FAILED`);
  }

  if (results.length > 0) {
    results.sort((a, b) => a.len - b.len);
    const best = results[0]!;
    if (!quiet) {
      console.log(
        `[Route] OK corner${best.corner} ${best.strategy} (len=${Math.round(best.len)}): ${fmt(best.route)}`,
      );
      // Double-check: does the winning route ACTUALLY hit any obstacles (including seg 0)?
      const allHits = findHits(best.route, 0);
      if (allHits.length > 0)
        console.warn(
          `[Route] ⚠️ WINNING ROUTE HITS OBSTACLES (checked from seg0):`,
          allHits,
        );
    }
    return best.route;
  }

  // Absolute fallback
  const fb = bestCorner(chipRect, labelAnchor.x, labelAnchor.y);
  const fbExit: [number, number] = chipZone
    ? [chipZone.x + chipZone.w + 4, fb.y]
    : [exitX, fb.y];
  // if (!quiet)
  //   console.log(
  //     `[Route] WARNING: no clear route found, using fallback: ${fmt([[fb.x, fb.y], fbExit, [labelAnchor.x, labelAnchor.y]])}`,
  //   );
  return [[fb.x, fb.y], fbExit, [labelAnchor.x, labelAnchor.y]];
}

// ── Route-aware slot assignment ──────────────────────────────────────────────
// Try all permutations (max 3! = 6), compute actual routed paths for each,
// and pick the assignment with shortest total path length.

export function bestSlotAssignment(
  chips: { x: number; y: number; w: number; h: number }[],
  slots: readonly { labelX: number; labelY: number }[],
  cardRightX: number,
  textObstacles: { x: number; y: number; w: number; h: number }[],
  chipZone: { x: number; y: number; w: number; h: number } | null,
): number[] {
  const n = chips.length;
  const slotIndices = slots.map((_, i) => i);

  let best: number[] = slotIndices.slice(0, n);
  let bestCost = Infinity;

  function evalPerm(perm: number[]): number {
    const labelBoxes = perm.map((si) => ({
      x: slots[si]!.labelX,
      y: slots[si]!.labelY,
      w: LABEL_WIDTH,
      h: LABEL_HEIGHT,
    }));

    const order = chips.map((_, i) => i);
    order.sort((a, b) => chips[a]!.y - chips[b]!.y);

    let totalLength = 0;
    for (let rank = 0; rank < n; rank++) {
      const i = order[rank]!;
      const chip = chips[i]!;
      const labelBox = labelBoxes[i]!;
      const exitX = cardRightX + CARD_EXIT_MARGIN + rank * EXIT_STAGGER;
      const chipCenterY = chip.y + chip.h / 2;
      const anchor = bestCorner(labelBox, exitX, chipCenterY);
      const otherLabels = labelBoxes.filter((_, j) => j !== i);
      const obstacles = [...otherLabels, ...textObstacles];
      const route = buildRoute(chip, anchor, exitX, obstacles, chipZone, true);
      totalLength += pathLength(route);
    }
    return totalLength;
  }

  function search(perm: number[], used: Set<number>) {
    if (perm.length === n) {
      const cost = evalPerm(perm);
      if (cost < bestCost) {
        bestCost = cost;
        best = [...perm];
      }
      return;
    }
    for (const si of slotIndices) {
      if (used.has(si)) continue;
      used.add(si);
      perm.push(si);
      search(perm, used);
      perm.pop();
      used.delete(si);
    }
  }

  search([], new Set());
  // console.log(
  //   `[Assignment] best:`,
  //   best.map(
  //     (s, i) => `chip${i}→slot${s}(${slots[s]!.labelX},${slots[s]!.labelY})`,
  //   ),
  //   `routedCost=${Math.round(bestCost)}`,
  // );
  return best;
}

/** Total polyline length */
export function pathLength(points: [number, number][]): number {
  let len = 0;
  for (let i = 1; i < points.length; i++) {
    const [x, y] = points[i]!;
    const [px, py] = points[i - 1]!;
    len += Math.sqrt((x - px) ** 2 + (y - py) ** 2);
  }
  return len;
}
