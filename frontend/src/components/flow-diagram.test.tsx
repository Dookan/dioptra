/** The E5 drawing: the server's wrapped lines, the hover title, the diamond, the branch label. */
import { render } from '@testing-library/react';
import { describe, expect, it } from 'vitest';

import type { Diagram } from '../api/projects';
import { FlowDiagram } from './flow-diagram';

const LABEL = 'if not isinstance(x, int)';

const DIAGRAM: Diagram = {
  path: 'src/f.py',
  function: 'f',
  line: 1,
  language: 'python',
  complexity: 2,
  mermaid: '',
  graph: { name: 'f', params: ['x'], nodes: [], edges: [] },
  layout: {
    width: 560,
    height: 420,
    nodes: [
      { id: 'n0', kind: 'start', label: 'f', line: 1, x: 170, y: 30, width: 220, height: 60, lines: ['f'] },
      {
        id: 'n1',
        kind: 'decision',
        label: LABEL,
        line: 2,
        x: 170,
        y: 150,
        width: 220,
        height: 60,
        lines: ['if not', 'isinstance(x, int)'],
      },
      { id: 'n2', kind: 'end', label: '', line: null, x: 30, y: 270, width: 220, height: 60, lines: [] },
    ],
    edges: [
      {
        source: 'n1',
        target: 'n2',
        label: 'true',
        back: false,
        points: [
          [280, 210],
          [280, 240],
          [140, 240],
          [140, 270],
        ],
      },
    ],
  },
  edited_text: null,
  edited_by_username: null,
  edited_at: null,
};

describe('flow diagram', () => {
  it('draws the lines the server wrapped, stacked and centred on the shape', () => {
    const { container } = render(<FlowDiagram diagram={DIAGRAM} />);
    const decision = [...container.querySelectorAll('.fd-label')][1]!;
    const spans = [...decision.querySelectorAll('tspan')].map((span) => [
      span.textContent,
      span.getAttribute('y'),
    ]);
    // Centre 180, two lines 12 apart: 178 and 190.
    expect(spans).toEqual([
      ['if not', '178'],
      ['isinstance(x, int)', '190'],
    ]);
  });

  it('gives the full label as the hover title, never on start or end', () => {
    const { container } = render(<FlowDiagram diagram={DIAGRAM} />);
    expect([...container.querySelectorAll('title')].map((node) => node.textContent)).toEqual([LABEL]);
  });

  it('draws a decision as a diamond wider than its box by the overhang', () => {
    const { container } = render(<FlowDiagram diagram={DIAGRAM} />);
    expect(container.querySelector('polygon.fd-decision')?.getAttribute('points')).toBe(
      '280,150 410,180 280,210 150,180',
    );
  });

  it('puts a turning branch label on its own horizontal run', () => {
    const { container } = render(<FlowDiagram diagram={DIAGRAM} />);
    const label = container.querySelector('.fd-edge-label')!;
    expect([label.getAttribute('x'), label.getAttribute('y'), label.getAttribute('text-anchor')]).toEqual([
      '210',
      '235',
      'middle',
    ]);
  });
});
