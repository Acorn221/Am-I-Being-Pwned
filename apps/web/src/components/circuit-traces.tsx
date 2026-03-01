/* eslint-disable @typescript-eslint/no-non-null-assertion, @typescript-eslint/no-unnecessary-condition */
import type { RefObject } from "react";
import { useEffect, useState } from "react";

import type { PermAnnotation } from "~/components/hero-slides";
import type { DebugBox, TraceData } from "./circuit-traces-geometry";
import {
  bestCorner,
  bestSlotAssignment,
  buildRoute,
  CARD_EXIT_MARGIN,
  EXIT_STAGGER,
  LABEL_AVOID_PAD,
  LABEL_HEIGHT,
  LABEL_SLOTS,
  LABEL_WIDTH,
  pointsToSvg,
  SHOW_DEBUG_BOXES,
} from "./circuit-traces-geometry";

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

        // console.log(
        //   `[Trace ${rank}] "${m.annotation.permission}" → slot(${slot.labelX},${slot.labelY})`,
        //   `exitX=${Math.round(exitX)}`,
        //   `chip=(${Math.round(m.chip.x)},${Math.round(m.chip.y)} ${Math.round(m.chip.w)}×${Math.round(m.chip.h)})`,
        //   `anchor=(${Math.round(anchor.x)},${Math.round(anchor.y)})`,
        //   `chipZone=${chipZone ? `(${Math.round(chipZone.x)},${Math.round(chipZone.y)} ${Math.round(chipZone.w)}×${Math.round(chipZone.h)})` : "none"}`,
        //   `obstacles: ${otherLabels.length} labels + ${textObstacles.length} text = ${allObstacles.length}`,
        // );

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
