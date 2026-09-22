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
          points={`${cx},${y} ${x + width},${cy} ${cx},${y + height} ${x},${cy}`}
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

function edgeLabelPosition(edge: PlacedEdge): [number, number] {
  const [x0, y0] = edge.points[0] ?? [0, 0];
  const [x1, y1] = edge.points[1] ?? [x0, y0];
  return [(x0 + x1) / 2 + 6, (y0 + y1) / 2 - 4];
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
        const [lx, ly] = edgeLabelPosition(edge);
        const key = `${edge.source}-${edge.target}-${edge.label}`;
        return (
          <g key={key} className={edge.back ? 'fd-edge fd-back' : 'fd-edge'}>
            <path d={edgePath(edge)} markerEnd={`url(#${markerId})`} />
            {edge.label !== '' && (
              <text className="fd-edge-label" x={lx} y={ly}>
                {EDGE_WORDS.has(edge.label) ? t(`design.edge.${edge.label}`) : edge.label}
              </text>
            )}
          </g>
        );
      })}
      {layout.nodes.map((node) => (
        <g key={node.id} className="fd-group">
          {nodeShape(node, clipId)}
          <text
            className="fd-label"
            x={node.x + node.width / 2}
            y={node.y + node.height / 2 + 4}
            textAnchor="middle"
          >
            {node.kind === 'start'
              ? t('design.node.start', { name: node.label })
              : node.kind === 'end'
                ? t('design.node.end')
                : node.label}
          </text>
        </g>
      ))}
    </svg>
  );
}
