import type { PermAnnotation } from "~/components/hero-slides";

/**
 * Predefined anchor slots for annotation labels positioned outside the card.
 * Coordinates are relative to the 480×440 outer container.
 * The card itself is at inset-x-[70px] top-[30px] → x:70..410, y:30..410.
 */
const SLOTS = [
  // Slot A: Top-right — label above-right, trace enters card top area
  { labelX: 370, labelY: -8, anchorX: 360, anchorY: 22, targetX: 280, targetY: 300 },
  // Slot B: Right side — label to the right, trace goes left into card
  { labelX: 380, labelY: 150, anchorX: 370, anchorY: 162, targetX: 280, targetY: 326 },
  // Slot C: Bottom-right — label below-right, trace goes up-left
  { labelX: 370, labelY: 310, anchorX: 360, anchorY: 300, targetX: 280, targetY: 352 },
] as const;

/**
 * Build a polyline path using only 0°, 45°, 90° segments.
 * Strategy: diagonal first to close the gap, then straight to the target.
 */
function buildTracePath(
  fromX: number,
  fromY: number,
  toX: number,
  toY: number,
): string {
  const dx = toX - fromX;
  const dy = toY - fromY;

  const diagDist = Math.min(Math.abs(dx), Math.abs(dy));
  const diagX = Math.sign(dx) * diagDist;
  const diagY = Math.sign(dy) * diagDist;

  const midX = fromX + diagX;
  const midY = fromY + diagY;

  return `M ${fromX} ${fromY} L ${midX} ${midY} L ${toX} ${toY}`;
}

interface CircuitTracesProps {
  annotations: PermAnnotation[];
  highlighted: boolean;
}

export function CircuitTraces({
  annotations,
  highlighted,
}: CircuitTracesProps) {
  if (annotations.length === 0) return null;

  const traces = annotations.slice(0, 3).map((ann, i) => {
    // eslint-disable-next-line @typescript-eslint/no-non-null-assertion
    const slot = SLOTS[i % SLOTS.length]!;
    const path = buildTracePath(slot.anchorX, slot.anchorY, slot.targetX, slot.targetY);
    const dx = slot.anchorX - slot.targetX;
    const dy = slot.anchorY - slot.targetY;
    const pathLength = Math.ceil(Math.sqrt(dx * dx + dy * dy) * 1.5);
    return { path, slot, annotation: ann, pathLength };
  });

  return (
    <svg
      className="pointer-events-none absolute inset-0 overflow-visible"
      style={{ zIndex: 50 }}
    >
      {traces.map(({ path, slot, annotation, pathLength }, i) => {
        const delay = 800 + i * 200;

        return (
          <g key={annotation.permission}>
            {/* Trace path */}
            <path
              d={path}
              fill="none"
              stroke="rgb(248 113 113)"
              strokeWidth={1.5}
              strokeOpacity={0.7}
              strokeDasharray={pathLength}
              strokeDashoffset={highlighted ? 0 : pathLength}
              style={{
                transition: `stroke-dashoffset 800ms ease-out ${delay}ms`,
              }}
            />

            {/* Endpoint dot at label anchor */}
            <circle
              cx={slot.anchorX}
              cy={slot.anchorY}
              r={3}
              fill="rgb(248 113 113)"
              opacity={highlighted ? 0.8 : 0}
              style={{ transition: `opacity 300ms ease-out ${delay}ms` }}
            />

            {/* Endpoint dot at target */}
            <circle
              cx={slot.targetX}
              cy={slot.targetY}
              r={3}
              fill="rgb(248 113 113)"
              opacity={highlighted ? 0.8 : 0}
              style={{ transition: `opacity 300ms ease-out ${delay}ms` }}
            />

            {/* Floating label */}
            <foreignObject
              x={slot.labelX}
              y={slot.labelY - 12}
              width={180}
              height={60}
              overflow="visible"
            >
              <div
                className="pointer-events-none w-max max-w-[170px] rounded-lg border border-red-500/20 bg-black/70 px-3 py-1.5 backdrop-blur-sm"
                style={{
                  opacity: highlighted ? 1 : 0,
                  transition: `opacity 400ms ease-out ${delay}ms`,
                }}
              >
                <p className="text-sm font-medium text-red-400">
                  {annotation.title}
                </p>
                <p className="text-muted-foreground text-xs">
                  {annotation.description}
                </p>
              </div>
            </foreignObject>
          </g>
        );
      })}
    </svg>
  );
}
