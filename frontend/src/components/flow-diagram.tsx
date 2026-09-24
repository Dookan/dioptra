/**
 * The flow diagram of one function, drawn from the server's layout.
 *
 * Everything is class-based SVG: the app ships under `style-src 'self'`, so
 * no inline style ever, and the picture is the AST's — the developer's edited
 * Mermaid text is shown beside it as text, never rendered as markup
 * (docs/threat-model.md → Flow diagrams). Labels are React text nodes.
 */
import { useId } from 'react';
import { useTranslation } from 'react-i18next';

import type { Diagram, PlacedEdge, PlacedNode } from '../api/projects';

interface Props {
  diagram: Diagram;
}

/** Edge labels the builder emits as words; anything else (a `case …`) is source text. */
const EDGE_WORDS = new Set(['true', 'false', 'loop', 'except', 'default']);

/** Mirrors `diagrams.DIAMOND_OVERHANG`: a decision is drawn wider than its box. */
const DIAMOND_OVERHANG = 20;

/** Baseline to baseline of a wrapped label at the diagram's 11px. */
const LINE_HEIGHT = 12;

function nodeShape(node: PlacedNode, clipId: string): React.ReactNode {
  const { x, y, width, height, kind } = node;
  const cx = x + width / 2;
  const cy = y + height / 2;
  switch (kind) {
    case 'start':
    case 'end':
      return <rect className={`fd-node fd-${kind}`} x={x} y={y} width={width} height={height} rx={height / 2} />;
    case 'decision':
    case 'loop':
      return (
        <polygon
          className={`fd-node fd-${kind}`}
          points={`${cx},${y} ${x + width + DIAMOND_OVERHANG},${cy} ${cx},${y + height} ${x - DIAMOND_OVERHANG},${cy}`}
        />
      );
    case 'return':
    case 'throw':
      return (
        <polygon
          className={`fd-node fd-${kind}`}
          points={`${x + 10},${y} ${x + width},${y} ${x + width - 10},${y + height} ${x},${y + height}`}
        />
      );
    default:
      return <rect className="fd-node fd-process" x={x} y={y} width={width} height={height} rx={6} clipPath={`url(#${clipId})`} />;
  }
}

function edgePath(edge: PlacedEdge): string {
  return edge.points.map(([x, y], index) => `${index === 0 ? 'M' : 'L'}${x},${y}`).join(' ');
}

/**
 * Mirrors `diagrams.edge_label_position`. Both branches of a decision leave
 * from the same point, so a label on the first segment drew "sí" over "no": a
 * branch that turns sideways carries its label on its own horizontal run.
 */
function edgeLabelPosition(edge: PlacedEdge): [number, number, 'start' | 'middle'] {
  const [x0, y0] = edge.points[0] ?? [0, 0];
  const turn = edge.points[1];
  const run = edge.points[2];
  if (!edge.back && turn !== undefined && run !== undefined && run[0] !== turn[0]) {
    return [(turn[0] + run[0]) / 2, turn[1] - 5, 'middle'];
  }
  const [x1, y1] = turn ?? [x0, y0];
  return [(x0 + x1) / 2 + 6, (y0 + y1) / 2 - 4, 'start'];
}

export function FlowDiagram({ diagram }: Props): React.ReactNode {
  const { t } = useTranslation();
  const markerId = useId();
  const clipId = useId();
  const { layout } = diagram;
  return (
    <svg
      className="flow-diagram"
      viewBox={`0 0 ${layout.width} ${layout.height}`}
      width={layout.width}
      height={layout.height}
      role="img"
      aria-label={t('design.diagram.alt', { name: diagram.function, count: diagram.complexity })}
    >
      <defs>
        <marker id={markerId} markerWidth="8" markerHeight="8" refX="7" refY="4" orient="auto">
          <path className="fd-arrow" d="M0,0 L8,4 L0,8 Z" />
        </marker>
        <clipPath id={clipId}>
          <rect x="0" y="0" width={layout.width} height={layout.height} />
        </clipPath>
      </defs>
      {layout.edges.map((edge) => {
        const [lx, ly, anchor] = edgeLabelPosition(edge);
        const key = `${edge.source}-${edge.target}-${edge.label}`;
        return (
          <g key={key} className={edge.back ? 'fd-edge fd-back' : 'fd-edge'}>
            <path d={edgePath(edge)} markerEnd={`url(#${markerId})`} />
            {edge.label !== '' && (
              <text className="fd-edge-label" x={lx} y={ly} textAnchor={anchor}>
                {EDGE_WORDS.has(edge.label) ? t(`design.edge.${edge.label}`) : edge.label}
              </text>
            )}
          </g>
        );
      })}
      {layout.nodes.map((node) => {
        const cx = node.x + node.width / 2;
        // Start and end carry our own words; every other shape draws the lines
        // the server wrapped to fit it, and the full label is the hover title.
        const lines =
          node.kind === 'start'
            ? [t('design.node.start', { name: node.label })]
            : node.kind === 'end'
              ? [t('design.node.end')]
              : node.lines;
        const first = node.y + node.height / 2 + 4 - ((lines.length - 1) * LINE_HEIGHT) / 2;
        return (
          <g key={node.id} className="fd-group">
            {node.kind !== 'start' && node.kind !== 'end' && <title>{node.label}</title>}
            {nodeShape(node, clipId)}
            <text className="fd-label" textAnchor="middle">
              {lines.map((line, index) => (
                // Lines are positional: the same text may repeat within one label.
                // eslint-disable-next-line react/no-array-index-key
                <tspan key={index} x={cx} y={first + index * LINE_HEIGHT}>
                  {line}
                </tspan>
              ))}
            </text>
          </g>
        );
      })}
    </svg>
  );
}
