/**
 * Inventory: the local copy's date is always on screen, hostile names render
 * as text, the mirror buttons need a role and a written reason and only
 * enqueue.
 */
import es from '../locales/es.json';
import { render, screen, waitFor } from '@testing-library/react';
import userEvent from '@testing-library/user-event';
import { describe, expect, it } from 'vitest';

import { App } from '../app';
import { AuthProvider } from '../auth/auth-provider';
import { NO_SESSION, stubFetch, type Routes } from '../test/http';

const HOSTILE = '<img src=x onerror=alert(1)>';
const ANALYSIS_ID = 'a-1';

function session(role: 'analyst' | 'developer' | 'admin') {
  const username = role === 'analyst' ? 'mmarin' : role === 'admin' ? 'amedina' : 'cperez';
  return {
    status: 200,
    body: {
      access_token: 'an-access-token',
      token_type: 'bearer',
      expires_in: 900,
      user: {
        id: '0f9b2a5e-0000-4000-8000-000000000001',
        username,
        display_name: 'Persona Demo',
        role,
        must_change_password: false,
      },
    },
  };
}

const INVENTORY = {
  totals: {
    projects: 1,
    components: 312,
    vulnerable_components: 7,
    open_cves: 8,
    not_affected: 2,
    outdated: 41,
    uncomparable: 1,
    by_severity: { critical: 0, high: 2, medium: 4, low: 1, info: 0 },
    capped: false,
  },
  licenses: [
    { name: 'MIT', count: 214 },
    { name: 'Apache-2.0', count: 71 },
  ],
  unlicensed: 1,
  projects: [
    {
      project_id: 'p-1',
      project_name: 'Formulario MINCYT — API',
      analysis_id: ANALYSIS_ID,
      ordinal: 3,
      analysed_at: '2026-09-22T10:00:00Z',
      components: 118,
      outdated: 18,
      open_cves: 3,
      vulnerable_components: 3,
      trend: -2,
      previous_analysis_id: 'a-0',
    },
  ],
  open: [
    {
      project_id: 'p-1',
      project_name: 'Formulario MINCYT — API',
      analysis_id: ANALYSIS_ID,
      component: HOSTILE,
      version: '4.17.15',
      ecosystem: 'npm',
      vulnerability_id: 'GHSA-p6mc-m468-83gw',
      cve: 'CVE-2020-8203',
      score: 7.4,
      severity: 'high',
      fixed_in: '4.17.19',
      summary: 'Prototype pollution',
      vex_state: 'exploitable',
      justification: null,
      verdict_by: null,
    },
    {
      project_id: 'p-1',
      project_name: 'Formulario MINCYT — API',
      analysis_id: ANALYSIS_ID,
      component: 'axios',
      version: '0.21.0',
      ecosystem: 'npm',
      vulnerability_id: 'GHSA-axios',
      cve: 'CVE-2020-28168',
      score: 5.9,
      severity: 'medium',
      fixed_in: '0.21.1',
      summary: null,
      vex_state: 'not_affected',
      justification: `el servidor no sigue redirecciones; la ruta vulnerable no se usa ${HOSTILE}`,
      verdict_by: 'mmarin',
    },
  ],
  crypto: [
    { primitive: 'hash', algorithm: 'SHA-1', weak: true, occurrences: 2, path: `auth/${HOSTILE}.js`, line: 18 },
    { primitive: 'cipher', algorithm: 'AES-256-GCM', weak: false, occurrences: 1, path: 'crypto/files.js', line: null },
  ],
  crypto_weak: 1,
  vulndb: {
    last_update: '2026-08-27T14:10:00Z',
    sync_enabled: true,
    interval_hours: 24,
    runs: [],
  },
};

function renderInventory(role: 'analyst' | 'developer' | 'admin', routes: Routes = {}) {
  globalThis.location.hash = '#/inventory';
  const calls = stubFetch({
    '/api/v1/auth/refresh': NO_SESSION,
    '/api/v1/auth/login': session(role),
    '/api/v1/inventory': { status: 200, body: INVENTORY },
    ...routes,
  });
  render(
    <AuthProvider>
      <App />
    </AuthProvider>,
  );
  return calls;
}

async function signIn(username: string) {
  const user = userEvent.setup();
  await user.type(await screen.findByLabelText(es.login.username), username);
  await user.type(screen.getByLabelText(es.login.password), 'correct-horse-battery-staple');
  await user.click(screen.getByRole('button', { name: es.login.submit }));
  return user;
}

function fill(template: string, values: Record<string, string | number>): string {
  return template.replace(/\{\{(\w+)\}\}/g, (_match, name: string) => String(values[name] ?? ''));
}

describe('inventory screen', () => {
  it('shows the totals, the local copy date and hostile names as text', async () => {
    renderInventory('developer');
    await signIn('cperez');
    expect(await screen.findByText(es.inventory.title)).toBeTruthy();
    expect(
      screen.getByText(
        fill(es.inventory.subtitle, { components: 312, projects: 1, vulnerable: 7, outdated: 41 }),
      ),
    ).toBeTruthy();
    expect(screen.getByText(fill(es.inventory.context_one, {}))).toBeTruthy();
    // The copy's date is on screen; the exact wording carries the date.
    expect(screen.getByText(/copia local del/)).toBeTruthy();
    // Component and path names from the audited tree never become markup.
    expect(screen.getAllByText(HOSTILE).length).toBeGreaterThan(0);
    expect(document.querySelector('img')).toBeNull();
    expect(screen.getByText('CVE-2020-8203', { exact: false })).toBeTruthy();
    expect(screen.getByText(es.inventory.vex.not_affected)).toBeTruthy();
    expect(screen.getByText(/el servidor no sigue redirecciones/)).toBeTruthy();
    expect(screen.getByText('SHA-1')).toBeTruthy();
    expect(screen.getByText(es.inventory.crypto.weak)).toBeTruthy();
    expect(screen.getByText(fill(es.inventory.trend.fewer_other, { count: 2 }))).toBeTruthy();
    // The developer reads; the mirror buttons are not theirs.
    expect(screen.queryByRole('button', { name: es.inventory.vulndb.syncNow })).toBeNull();
    expect(screen.queryByRole('button', { name: es.inventory.vulndb.import })).toBeNull();
    // Downloads are everyone's, and act on the selected project.
    expect(screen.getByRole('button', { name: es.inventory.download.sbom })).toBeTruthy();
    expect(screen.getByRole('button', { name: es.inventory.download.vex })).toBeTruthy();
  });

  it('filters the open list without asking the server', async () => {
    renderInventory('analyst');
    const user = await signIn('mmarin');
    await screen.findByText(es.inventory.title);
    await user.click(screen.getByRole('button', { name: es.inventory.open.filter.unresolved }));
    expect(screen.queryByText(es.inventory.vex.not_affected)).toBeNull();
    expect(screen.getAllByText(HOSTILE).length).toBeGreaterThan(0);
    await user.click(screen.getByRole('button', { name: es.inventory.open.filter.high }));
    expect(screen.queryByText('axios')).toBeNull();
  });

  it('lets the analyst request a sync behind a written reason, and only enqueues', async () => {
    const calls = renderInventory('analyst', {
      '/api/v1/inventory/vulndb/sync': { status: 202 },
    });
    const user = await signIn('mmarin');
    await user.click(await screen.findByRole('button', { name: es.inventory.vulndb.syncNow }));
    const confirm = screen.getByRole('button', { name: es.inventory.vulndb.confirmSync });
    expect((confirm as HTMLButtonElement).disabled).toBe(true);
    await user.type(
      screen.getByLabelText(es.inventory.vulndb.reasonLabel),
      'Actualización semanal antes de firmar el reporte.',
    );
    expect((confirm as HTMLButtonElement).disabled).toBe(false);
    await user.click(confirm);
    await waitFor(() => {
      expect(screen.getByText(es.inventory.syncQueued)).toBeTruthy();
    });
    const posted = (calls.mock.calls as unknown as [RequestInfo | URL, RequestInit | undefined][]).find(
      ([url, init]) => String(url) === '/api/v1/inventory/vulndb/sync' && init?.method === 'POST',
    );
    expect(JSON.parse(String(posted?.[1]?.body)).justification).toContain('semanal');
  });

  it('says plainly when the operator disabled the sync and offers only the import', async () => {
    renderInventory('admin', {
      '/api/v1/inventory': {
        status: 200,
        body: { ...INVENTORY, vulndb: { ...INVENTORY.vulndb, sync_enabled: false, last_update: null } },
      },
    });
    await signIn('amedina');
    expect(await screen.findByText(es.inventory.vulndb.disabledNone)).toBeTruthy();
    expect(screen.queryByRole('button', { name: es.inventory.vulndb.syncNow })).toBeNull();
    expect(screen.getByRole('button', { name: es.inventory.vulndb.import })).toBeTruthy();
  });
});
