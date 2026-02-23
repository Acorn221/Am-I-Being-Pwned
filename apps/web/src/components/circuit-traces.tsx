/* eslint-disable @typescript-eslint/no-unnecessary-condition, @typescript-eslint/no-non-null-assertion */
import type { RefObject } from "react";
import { useEffect, useState } from "react";

import type { PermAnnotation } from "~/components/hero-slides";

/** Set to true to render debug bounding boxes for traces/labels/chips */
const SHOW_DEBUG_BOXES = false;

// ── Label slots scattered around the card ───────────────────────────────────
// Container: 480×440, card: ~x:70..420, y:22..402 (after front card rotation).
// labelX/labelY = foreignObject top-left. Anchor point is computed dynamically.
const LABEL_WIDTH = 190;
const LABEL_HEIGHT = 48;
const LABEL_SLOTS = [
  { labelX: 420, labelY: 100 },
  { labelX: 420, labelY: 350 },
  { labelX: 280, labelY: -50 },
];

// ── Types ───────────────────────────────────────────────────────────────────
interface DebugBox {
  x: number;
  y: number;
  w: number;
  h: number;
  color: string;
  label?: string;
  /** Rotation in degrees, around the box center */
  rotate?: number;
}

interface TraceData {
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
function bestCorner(
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
function pointsToSvg(points: [number, number][]): {
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

const CARD_EXIT_MARGIN = 12; // px past the card's right edge
const EXIT_STAGGER = 16; // px between each trace's exit column
const LABEL_AVOID_PAD = 8; // px padding around labels for avoidance

/** Check if a line segment (p1→p2) intersects an axis-aligned rectangle. */
function segmentHitsBox(
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
function routeHitsObstacles(
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
function buildRoute(
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
    if (!quiet)
      console.log(`  [corner${ci}] direct BLOCKED: ${fmt(d)}`, findHits(d, 0));

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
    if (!quiet)
      console.log(
        `  [corner${ci}] exit→anchor BLOCKED: ${fmt(r1)}`,
        findHits(r1, 1),
      );

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
    if (!quiet)
      console.log(
        `  [corner${ci}] exit→col→anchor BLOCKED: ${fmt(r2)}`,
        findHits(r2, 1),
      );

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

    if (!found && !quiet) console.log(`  [corner${ci}] ALL strategies FAILED`);
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
  if (!quiet)
    console.log(
      `[Route] WARNING: no clear route found, using fallback: ${fmt([[fb.x, fb.y], fbExit, [labelAnchor.x, labelAnchor.y]])}`,
    );
  return [[fb.x, fb.y], fbExit, [labelAnchor.x, labelAnchor.y]];
}

// ── Route-aware slot assignment ──────────────────────────────────────────────
// Try all permutations (max 3! = 6), compute actual routed paths for each,
// and pick the assignment with shortest total path length.

function bestSlotAssignment(
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
  console.log(
    `[Assignment] best:`,
    best.map(
      (s, i) => `chip${i}→slot${s}(${slots[s]!.labelX},${slots[s]!.labelY})`,
    ),
    `routedCost=${Math.round(bestCost)}`,
  );
  return best;
}

/** Total polyline length */
function pathLength(points: [number, number][]): number {
  let len = 0;
  for (let i = 1; i < points.length; i++) {
    const [x, y] = points[i]!;
    const [px, py] = points[i - 1]!;
    len += Math.sqrt((x - px) ** 2 + (y - py) ** 2);
  }
  return len;
}

// ── Component ───────────────────────────────────────────────────────────────

interface CircuitTracesProps {
  annotations: PermAnnotation[];
  highlighted: boolean;
  containerRef: RefObject<HTMLDivElement | null>;
}

export function CircuitTraces({
  annotations,
  highlighted,
  containerRef,
}: CircuitTracesProps) {
  const [traces, setTraces] = useState<TraceData[]>([]);
  const [animateIn, setAnimateIn] = useState(false);
  const [debugBoxes, setDebugBoxes] = useState<DebugBox[]>([]);
  const [measuredLabelBoxes, setMeasuredLabelBoxes] = useState<DebugBox[]>([]);

  useEffect(() => {
    if (!highlighted || !containerRef.current || annotations.length === 0) {
      // eslint-disable-next-line react-hooks/set-state-in-effect -- intentional cleanup when highlight ends
      setTraces([]);
      setAnimateIn(false);
      return;
    }

    let animateRafId = 0;
    const rafId = requestAnimationFrame(() => {
      const container = containerRef.current;
      if (!container) return;

      const containerRect = container.getBoundingClientRect();

      // ── Measure card rotation & right edge ──────────────────────────
      const frontCard = container.querySelector("[data-card-front]");
      const cardRightX = frontCard
        ? frontCard.getBoundingClientRect().right - containerRect.left
        : 420; // fallback

      let cardAngle = 0;
      if (frontCard) {
        const matrix = new DOMMatrix(getComputedStyle(frontCard).transform);
        cardAngle = Math.atan2(matrix.b, matrix.a) * (180 / Math.PI);
      }

      // Precompute rotation correction factors for undoing AABB inflation
      const rad = Math.abs((cardAngle * Math.PI) / 180);
      const cos = Math.cos(rad);
      const sin = Math.sin(rad);
      const det = cos * cos - sin * sin;

      /** Undo AABB inflation from card rotation: recover true (pre-rotation) size */
      const unrotateAABB = (aabbW: number, aabbH: number) => {
        if (det === 0) return { w: aabbW, h: aabbH };
        return {
          w: (aabbW * cos - aabbH * sin) / det,
          h: (aabbH * cos - aabbW * sin) / det,
        };
      };

      // ── Measure chip positions (corrected for card rotation) ──────
      const chipEls =
        container.querySelectorAll<HTMLSpanElement>("[data-perm]");
      const chipPositions = new Map<
        string,
        { x: number; y: number; w: number; h: number }
      >();

      chipEls.forEach((el) => {
        const perm = el.dataset.perm;
        if (!perm) return;
        const rect = el.getBoundingClientRect();
        // AABB center is correct; offsetWidth/Height give true pre-transform size
        const cx = rect.left + rect.width / 2 - containerRect.left;
        const cy = rect.top + rect.height / 2 - containerRect.top;
        const w = el.offsetWidth;
        const h = el.offsetHeight;
        chipPositions.set(perm, {
          x: cx - w / 2,
          y: cy - h / 2,
          w,
          h,
        });
      });

      // ── Match annotations → chips, cap at slot count ────────────────
      const matched: {
        annotation: PermAnnotation;
        chip: { x: number; y: number; w: number; h: number };
      }[] = [];
      for (const ann of annotations) {
        const chip = chipPositions.get(ann.permission);
        if (!chip) continue;
        matched.push({ annotation: ann, chip });
        if (matched.length >= LABEL_SLOTS.length) break;
      }

      if (matched.length === 0) {
        setTraces([]);
        return;
      }

      // ── Measure text obstacles on the front card (corrected for rotation) ─
      const textObstacles: { x: number; y: number; w: number; h: number }[] =
        [];
      if (frontCard) {
        const obstacleEls = frontCard.querySelectorAll("[data-trace-obstacle]");
        obstacleEls.forEach((el) => {
          const range = document.createRange();
          range.selectNodeContents(el);
          const rr = range.getBoundingClientRect();
          const cx = rr.left + rr.width / 2 - containerRect.left;
          const cy = rr.top + rr.height / 2 - containerRect.top;
          const { w, h } = unrotateAABB(rr.width, rr.height);
          textObstacles.push({ x: cx - w / 2, y: cy - h / 2, w, h });
        });
      }
      // Compute chip zone bounding box from already-corrected chip positions
      let czMinX = Infinity,
        czMinY = Infinity,
        czMaxX = -Infinity,
        czMaxY = -Infinity;
      for (const chip of chipPositions.values()) {
        czMinX = Math.min(czMinX, chip.x);
        czMinY = Math.min(czMinY, chip.y);
        czMaxX = Math.max(czMaxX, chip.x + chip.w);
        czMaxY = Math.max(czMaxY, chip.y + chip.h);
      }
      const chipZone =
        czMinX < Infinity
          ? { x: czMinX, y: czMinY, w: czMaxX - czMinX, h: czMaxY - czMinY }
          : null;

      // ── Route-aware slot assignment ────────────────────────────────
      const slotAssignment = bestSlotAssignment(
        matched.map((m) => m.chip),
        LABEL_SLOTS,
        cardRightX,
        textObstacles,
        chipZone,
      );

      const allLabelBoxes = matched.map((_, i) => {
        const slot = LABEL_SLOTS[slotAssignment[i]!]!;
        return {
          x: slot.labelX,
          y: slot.labelY,
          w: LABEL_WIDTH,
          h: LABEL_HEIGHT,
        };
      });

      // ── Sort by chip Y so staggered exits look natural ────────────────
      const order = matched.map((_, i) => i);
      order.sort((a, b) => matched[a]!.chip.y - matched[b]!.chip.y);

      // ── Build deterministic polyline routes ─────────────────────────
      const computedMap = new Map<number, TraceData>();

      for (let rank = 0; rank < order.length; rank++) {
        const i = order[rank]!;
        const m = matched[i]!;
        const slotIdx = slotAssignment[i]!;
        const slot = LABEL_SLOTS[slotIdx]!;

        const labelBox = allLabelBoxes[i]!;

        // Stagger exit X so traces don't overlap horizontally
        const exitX = cardRightX + CARD_EXIT_MARGIN + rank * EXIT_STAGGER;

        // Label anchor: corner of label closest to the exit point at chip Y
        const chipCenterY = m.chip.y + m.chip.h / 2;
        const anchor = bestCorner(labelBox, exitX, chipCenterY);

        // Obstacles for phase 2: other labels + text obstacles (NOT individual chips)
        const otherLabels = allLabelBoxes.filter((_, j) => j !== i);
        const allObstacles = [...otherLabels, ...textObstacles];

        console.log(
          `[Trace ${rank}] "${m.annotation.permission}" → slot(${slot.labelX},${slot.labelY})`,
          `exitX=${Math.round(exitX)}`,
          `chip=(${Math.round(m.chip.x)},${Math.round(m.chip.y)} ${Math.round(m.chip.w)}×${Math.round(m.chip.h)})`,
          `anchor=(${Math.round(anchor.x)},${Math.round(anchor.y)})`,
          `chipZone=${chipZone ? `(${Math.round(chipZone.x)},${Math.round(chipZone.y)} ${Math.round(chipZone.w)}×${Math.round(chipZone.h)})` : "none"}`,
          `obstacles: ${otherLabels.length} labels + ${textObstacles.length} text = ${allObstacles.length}`,
        );

        // Build the polyline
        const pixels = buildRoute(
          m.chip,
          anchor,
          exitX,
          allObstacles,
          chipZone,
        );
        const { path, length } = pointsToSvg(pixels);

        const startPt = pixels[0]!;

        computedMap.set(i, {
          annotation: m.annotation,
          chipX: startPt[0],
          chipY: startPt[1],
          anchorX: anchor.x,
          anchorY: anchor.y,
          labelX: slot.labelX,
          labelY: slot.labelY,
          path,
          pathLength: length,
        });
      }

      const computed: TraceData[] = [];
      for (let i = 0; i < matched.length; i++) {
        const td = computedMap.get(i);
        if (td) computed.push(td);
      }

      // ── Debug: collect bounding boxes ──────────────────────────────
      const boxes: DebugBox[] = [];

      // Chip zone bounding box
      if (chipZone) {
        boxes.push({
          x: chipZone.x,
          y: chipZone.y,
          w: chipZone.w,
          h: chipZone.h,
          color: "rgba(250,204,21,0.5)",
          label: "chip zone",
        });
      }

      // Label bounding boxes (with avoidance padding)
      for (const lb of allLabelBoxes) {
        boxes.push({
          x: lb.x - LABEL_AVOID_PAD,
          y: lb.y - LABEL_AVOID_PAD,
          w: lb.w + LABEL_AVOID_PAD * 2,
          h: lb.h + LABEL_AVOID_PAD * 2,
          color: "rgba(59,130,246,0.4)",
          label: "label avoid",
        });
        // Actual label box (no padding)
        boxes.push({
          x: lb.x,
          y: lb.y,
          w: lb.w,
          h: lb.h,
          color: "rgba(59,130,246,0.7)",
        });
      }

      // Card right edge
      boxes.push({
        x: cardRightX,
        y: 0,
        w: 1,
        h: 440,
        color: "rgba(34,197,94,0.5)",
        label: "card edge",
      });

      // Exit columns (staggered)
      for (let rank = 0; rank < order.length; rank++) {
        const ex = cardRightX + CARD_EXIT_MARGIN + rank * EXIT_STAGGER;
        boxes.push({
          x: ex,
          y: 0,
          w: 1,
          h: 440,
          color: "rgba(168,85,247,0.3)",
          label: `exit ${rank}`,
        });
      }

      // Text obstacles ONLY from the front card (rotated to match card)
      // Use Range API to measure actual text bounds (not block-level element width)
      if (frontCard) {
        const obstacleEls = frontCard.querySelectorAll("[data-trace-obstacle]");
        obstacleEls.forEach((el) => {
          const range = document.createRange();
          range.selectNodeContents(el);
          const rangeRect = range.getBoundingClientRect();
          const cx = rangeRect.left + rangeRect.width / 2 - containerRect.left;
          const cy = rangeRect.top + rangeRect.height / 2 - containerRect.top;
          const { w, h } = unrotateAABB(rangeRect.width, rangeRect.height);
          boxes.push({
            x: cx - w / 2,
            y: cy - h / 2,
            w,
            h,
            color: "rgba(239,68,68,0.3)",
            label: "text",
            rotate: cardAngle,
          });
        });
      }

      // All chip badges on the front card (rotated to match card)
      chipEls.forEach((el) => {
        const rect = el.getBoundingClientRect();
        const cx = rect.left + rect.width / 2 - containerRect.left;
        const cy = rect.top + rect.height / 2 - containerRect.top;
        const w = el.offsetWidth;
        const h = el.offsetHeight;
        boxes.push({
          x: cx - w / 2,
          y: cy - h / 2,
          w,
          h,
          color: "rgba(250,204,21,0.3)",
          label: el.dataset.perm,
          rotate: cardAngle,
        });
      });

      setDebugBoxes(boxes);
      setAnimateIn(false);
      setTraces(computed);

      // After the hidden-state frame paints, flip to trigger CSS transitions
      animateRafId = requestAnimationFrame(() => {
        setAnimateIn(true);
      });
    });

    return () => {
      cancelAnimationFrame(rafId);
      cancelAnimationFrame(animateRafId);
    };
  }, [highlighted, annotations, containerRef]);

  // Second pass: measure actual rendered label sizes
  useEffect(() => {
    if (traces.length === 0 || !containerRef.current) {
      const id = requestAnimationFrame(() => setMeasuredLabelBoxes([]));
      return () => cancelAnimationFrame(id);
    }
    const rafId = requestAnimationFrame(() => {
      const container = containerRef.current;
      if (!container) return;
      const containerRect = container.getBoundingClientRect();
      const labelEls =
        container.querySelectorAll<HTMLDivElement>("[data-trace-label]");
      const boxes: DebugBox[] = [];
      labelEls.forEach((el) => {
        const rect = el.getBoundingClientRect();
        // Actual label box
        boxes.push({
          x: rect.left - containerRect.left,
          y: rect.top - containerRect.top,
          w: rect.width,
          h: rect.height,
          color: "rgba(16,185,129,0.8)",
          label: `actual: ${Math.round(rect.width)}×${Math.round(rect.height)}`,
        });
        // With avoidance padding
        boxes.push({
          x: rect.left - containerRect.left - LABEL_AVOID_PAD,
          y: rect.top - containerRect.top - LABEL_AVOID_PAD,
          w: rect.width + LABEL_AVOID_PAD * 2,
          h: rect.height + LABEL_AVOID_PAD * 2,
          color: "rgba(16,185,129,0.4)",
          label: "actual avoid",
        });
      });
      setMeasuredLabelBoxes(boxes);
    });
    return () => cancelAnimationFrame(rafId);
  }, [traces, containerRef]);

  if (traces.length === 0) return null;

  return (
    <svg
      className="pointer-events-none absolute inset-0 overflow-visible"
      style={{ zIndex: 50 }}
    >
      {/* Debug: measured label boxes (green) */}
      {SHOW_DEBUG_BOXES &&
        measuredLabelBoxes.map((box, i) => (
          <g key={`mlabel-${i}`}>
            <rect
              x={box.x}
              y={box.y}
              width={box.w}
              height={box.h}
              fill="none"
              stroke={box.color}
              strokeWidth={1.5}
              strokeDasharray={box.w > 2 ? "4 2" : undefined}
            />
            {box.label && (
              <text
                x={box.x + 2}
                y={box.y - 2}
                fill={box.color}
                fontSize={8}
                fontFamily="monospace"
              >
                {box.label}
              </text>
            )}
          </g>
        ))}
      {/* Debug bounding boxes */}
      {SHOW_DEBUG_BOXES &&
        debugBoxes.map((box, i) => {
          const cx = box.x + box.w / 2;
          const cy = box.y + box.h / 2;
          const rot = box.rotate
            ? `rotate(${box.rotate} ${cx} ${cy})`
            : undefined;
          return (
            <g key={`debug-${i}`} transform={rot}>
              <rect
                x={box.x}
                y={box.y}
                width={box.w}
                height={box.h}
                fill="none"
                stroke={box.color}
                strokeWidth={1}
                strokeDasharray={box.w > 2 ? "4 2" : undefined}
              />
              {box.label && (
                <text
                  x={box.x + 2}
                  y={box.y - 2}
                  fill={box.color}
                  fontSize={8}
                  fontFamily="monospace"
                >
                  {box.label}
                </text>
              )}
            </g>
          );
        })}
      {traces.map((trace, i) => {
        // Dynamic timing: keep total window ~900ms regardless of trace count
        const n = traces.length;
        const stagger = n > 1 ? Math.min(150, 400 / (n - 1)) : 0;
        const traceDuration = Math.max(300, 500 - n * 50);
        const delay = 100 + i * stagger;
        const arriveDelay = delay + traceDuration;

        return (
          <g key={trace.annotation.permission}>
            {/* Trace path - draws from chip to label */}
            <path
              d={trace.path}
              fill="none"
              stroke="rgb(248 113 113)"
              strokeWidth={1.5}
              strokeOpacity={0.7}
              strokeDasharray={trace.pathLength}
              strokeDashoffset={animateIn ? 0 : trace.pathLength}
              style={{
                transition: `stroke-dashoffset ${traceDuration}ms ease-out ${delay}ms`,
              }}
            />

            {/* Dot at chip - appears immediately */}
            <circle
              cx={trace.chipX}
              cy={trace.chipY}
              r={3}
              fill="rgb(248 113 113)"
              opacity={animateIn ? 0.8 : 0}
              style={{ transition: `opacity 200ms ease-out ${delay}ms` }}
            />

            {/* Dot at label anchor - appears when trace arrives */}
            <circle
              cx={trace.anchorX}
              cy={trace.anchorY}
              r={3}
              fill="rgb(248 113 113)"
              opacity={animateIn ? 0.8 : 0}
              style={{ transition: `opacity 200ms ease-out ${arriveDelay}ms` }}
            />

            {/* Floating label - fades in when trace arrives */}
            <foreignObject
              x={trace.labelX}
              y={trace.labelY}
              width={200}
              height={60}
              overflow="visible"
            >
              <div
                data-trace-label={trace.annotation.permission}
                className="pointer-events-none w-max max-w-[190px] rounded-lg border border-red-500/20 bg-black/70 px-3 py-1.5 backdrop-blur-sm"
                style={{
                  opacity: animateIn ? 1 : 0,
                  transition: `opacity 250ms ease-out ${arriveDelay}ms`,
                }}
              >
                <p className="text-sm font-medium text-red-400">
                  {trace.annotation.title}
                </p>
                <p className="text-muted-foreground text-xs">
                  {trace.annotation.description}
                </p>
              </div>
            </foreignObject>
          </g>
        );
      })}
    </svg>
  );
}
