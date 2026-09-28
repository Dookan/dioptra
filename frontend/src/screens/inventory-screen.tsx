/**
 * The software inventory of the factory. Mockup anchor: screen 11 "Inventario".
 *
 * Everything shown here was read from the LOCAL copy of OSV + NVD and from
 * the stored SBOMs; the date of that copy is always on screen and nothing
 * on this page implies a live lookup (docs/ui-model.md → principle 5). The
 * two buttons that touch the mirror only ENQUEUE a job, behind a written
 * reason. Component names, versions, licences and advisory summaries are
 * hostile text and render as React text nodes only.
 */
import { useEffect, useId, useState } from 'react';
import { useTranslation } from 'react-i18next';

import { ApiError } from '../api/client';
import * as api from '../api/inventory';
import type { Inventory, InventoryDocument, OpenCveRow, ProjectInventoryRow } from '../api/inventory';
import { saveDownload } from '../api/projects';
import { useAuth } from '../auth/auth-context';
import { AppShell } from '../components/app-shell';
import { widthClass } from '../components/width-class';
import type { Route } from '../navigation/use-route';

interface Props {
  route: Extract<Route, { kind: 'inventory' }>;
  onNavigate: (route: Route) => void;
}

type Filter = 'all' | 'high' | 'unresolved';
/** Mirrors backend/app/core/text.py::MIN_JUSTIFICATION_CHARS — the server is the gate. */
const MIN_JUSTIFICATION = 10;
const DOCUMENTS: InventoryDocument[] = ['sbom', 'cbom', 'vex', 'csv'];

function severityTone(severity: string | null): 'err' | 'warn' | 'info' {
  if (severity === 'critical' || severity === 'high') return 'err';
  if (severity === 'medium') return 'warn';
  return 'info';
}

function rowMatches(row: OpenCveRow, filter: Filter): boolean {
  if (filter === 'high') return row.severity === 'critical' || row.severity === 'high';
  if (filter === 'unresolved') return row.vex_state !== 'not_affected';
  return true;
}

function OpenRow({ row }: { row: OpenCveRow }): React.ReactNode {
  const { t } = useTranslation();
  const tone = severityTone(row.severity);
  const applies = row.vex_state !== 'not_affected';
  return (
    <li className="rowline">
      <span className={`prio ${tone}`} aria-hidden="true">
        {t(`inventory.prio.${tone}`)}
      </span>
      <div className="grow">
        <b>{row.component}</b> <span className="mono">{row.version ?? ''}</span> · {row.project_name}
        <div className="sub">
          {row.cve}
          {row.score !== null && ` · ${t('inventory.cvss', { score: row.score.toFixed(1) })}`}
          {row.fixed_in !== null && ` · ${t('inventory.fixedIn', { version: row.fixed_in })}`}
          {row.justification !== null && row.verdict_by !== null
            ? ` · ${row.verdict_by}: "${row.justification}"`
            : applies && row.fixed_in !== null && (
                <>
                  {' · '}
                  <b>{t('inventory.whatToDoLabel')}</b> {t('inventory.whatToDo')}
                </>
              )}
        </div>
      </div>
      <span className={applies ? (tone === 'err' ? 'badge err' : 'badge warn') : 'badge ok'}>
        {t(`inventory.vex.${row.vex_state}`)}
      </span>
    </li>
  );
}

function ProjectRow({
  row,
  selected,
  onSelect,
}: {
  row: ProjectInventoryRow;
  selected: boolean;
  onSelect: () => void;
}): React.ReactNode {
  const { t, i18n } = useTranslation();
  const date = new Date(row.analysed_at).toLocaleDateString(i18n.resolvedLanguage, {
    dateStyle: 'medium',
  });
  const trendClass = row.trend === null ? 'sub' : row.trend < 0 ? 'sub ok' : row.trend > 0 ? 'sub bad' : 'sub';
  return (
    <li className={selected ? 'rowline sel' : 'rowline'}>
      <button type="button" className="grow linklike" onClick={onSelect} aria-pressed={selected}>
        <b>{row.project_name}</b>
        <div className="sub">
          {t('inventory.projectLine', {
            ordinal: row.ordinal,
            date,
            components: row.components,
            outdated: row.outdated,
          })}
        </div>
        <div className={trendClass}>
          {row.trend === null
            ? t('inventory.trend.first')
            : row.trend < 0
              ? t('inventory.trend.fewer', { ordinal: row.ordinal, count: -row.trend })
              : row.trend > 0
                ? t('inventory.trend.more', { ordinal: row.ordinal, count: row.trend })
                : t('inventory.trend.same', { ordinal: row.ordinal })}
        </div>
      </button>
      <span className={row.open_cves > 0 ? 'badge err' : 'badge ok'}>
        {t('inventory.cveCount', { count: row.open_cves })}
      </span>
    </li>
  );
}

export function InventoryScreen({ route, onNavigate }: Props): React.ReactNode {
  const { t, i18n } = useTranslation();
  const { accessToken, user } = useAuth();
  const reasonId = useId();
  const fileId = useId();
  const [inventory, setInventory] = useState<Inventory | null>(null);
  const [errorKey, setErrorKey] = useState<string | null>(null);
  const [notice, setNotice] = useState<string | null>(null);
  const [filter, setFilter] = useState<Filter>('all');
  const [selected, setSelected] = useState<string | null>(null);
  const [action, setAction] = useState<'sync' | 'import' | null>(null);
  const [reason, setReason] = useState('');
  const [file, setFile] = useState<File | null>(null);
  const [busy, setBusy] = useState(false);

  function load(token: string): Promise<void> {
    return api.getInventory(token).then((loaded) => {
      setInventory(loaded);
      setSelected((current) => current ?? loaded.projects[0]?.analysis_id ?? null);
    });
  }

  useEffect(() => {
    if (accessToken === null) return;
    let cancelled = false;
    load(accessToken).catch((error: unknown) => {
      if (!cancelled) setErrorKey(error instanceof ApiError ? error.messageKey : 'errors.internal');
    });
    return () => {
      cancelled = true;
    };
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [accessToken]);

  const mayRefresh = user?.role === 'admin' || user?.role === 'analyst';
  const lastUpdate =
    inventory?.vulndb.last_update === null || inventory?.vulndb.last_update === undefined
      ? null
      : new Date(inventory.vulndb.last_update).toLocaleString(i18n.resolvedLanguage, {
          dateStyle: 'medium',
          timeStyle: 'short',
        });

  async function submit(): Promise<void> {
    if (accessToken === null || action === null) return;
    setBusy(true);
    setErrorKey(null);
    setNotice(null);
    try {
      if (action === 'sync') {
        await api.requestSync(accessToken, reason);
        setNotice('inventory.syncQueued');
      } else if (file !== null) {
        await api.importDump(accessToken, file, reason);
        setNotice('inventory.importQueued');
      }
      setAction(null);
      setReason('');
      setFile(null);
      await load(accessToken);
    } catch (error) {
      setErrorKey(error instanceof ApiError ? error.messageKey : 'errors.internal');
    } finally {
      setBusy(false);
    }
  }

  async function download(kind: InventoryDocument): Promise<void> {
    if (accessToken === null || selected === null) return;
    setErrorKey(null);
    try {
      saveDownload(await api.downloadInventoryDocument(accessToken, selected, kind));
    } catch (error) {
      setErrorKey(error instanceof ApiError ? error.messageKey : 'errors.internal');
    }
  }

  const totals = inventory?.totals;
  const upToDate =
    totals === undefined || totals.components === 0
      ? 100
      : Math.round((100 * (totals.components - totals.outdated)) / totals.components);
  const canSubmit =
    reason.trim().length >= MIN_JUSTIFICATION && (action === 'sync' || file !== null) && !busy;
  const context =
    totals === undefined
      ? undefined
      : t('inventory.context', { count: totals.projects });

  return (
    <AppShell route={route} onNavigate={onNavigate} context={context}>
      {errorKey !== null && (
        <p className="alert" role="alert">
          {t(errorKey)}
        </p>
      )}
      <div className="pagehead">
        <h2>{t('inventory.title')}</h2>
        {totals !== undefined && (
          <p className="sub">
            {t('inventory.subtitle', {
              components: totals.components,
              projects: totals.projects,
              vulnerable: totals.vulnerable_components,
              outdated: totals.outdated,
            })}
            {totals.capped && ` ${t('inventory.capped')}`}
          </p>
        )}
      </div>
      {inventory !== null && (
        <>
          <section className="nextstep info">
            <div className="txt">
              <b>
                {!inventory.vulndb.sync_enabled && lastUpdate === null
                  ? t('inventory.vulndb.disabledNone')
                  : lastUpdate === null
                    ? t('inventory.vulndb.none')
                    : t('inventory.vulndb.copyOf', { date: lastUpdate })}
              </b>
              <div>
                {inventory.vulndb.sync_enabled
                  ? t('inventory.vulndb.bodySync', { hours: inventory.vulndb.interval_hours })
                  : t('inventory.vulndb.bodyImportOnly')}
              </div>
            </div>
            {mayRefresh && action === null && (
              <>
                {inventory.vulndb.sync_enabled && (
                  <button
                    type="button"
                    className="btn"
                    onClick={() => {
                      setAction('sync');
                    }}
                  >
                    {t('inventory.vulndb.syncNow')}
                  </button>
                )}
                <button
                  type="button"
                  className="btn ghost"
                  onClick={() => {
                    setAction('import');
                  }}
                >
                  {t('inventory.vulndb.import')}
                </button>
              </>
            )}
          </section>
          {mayRefresh && action !== null && (
            <section className="panel reason">
              <h4>
                {action === 'sync' ? t('inventory.vulndb.syncNow') : t('inventory.vulndb.import')}
              </h4>
              <p className="hint">{t('inventory.vulndb.reasonHint')}</p>
              {action === 'import' && (
                <div className="field">
                  <label htmlFor={fileId}>{t('inventory.vulndb.fileLabel')}</label>
                  <input
                    id={fileId}
                    type="file"
                    accept=".zip,.json,.gz"
                    onChange={(event) => {
                      setFile(event.target.files?.[0] ?? null);
                    }}
                  />
                  <p className="hint">{t('inventory.vulndb.fileHint')}</p>
                </div>
              )}
              <div className="field">
                <label htmlFor={reasonId}>{t('inventory.vulndb.reasonLabel')}</label>
                <textarea
                  id={reasonId}
                  className="input textarea"
                  value={reason}
                  onChange={(event) => {
                    setReason(event.target.value);
                  }}
                />
              </div>
              <div className="actions">
                <button
                  type="button"
                  className="btn primary"
                  disabled={!canSubmit}
                  onClick={() => void submit()}
                >
                  {action === 'sync' ? t('inventory.vulndb.confirmSync') : t('inventory.vulndb.confirmImport')}
                </button>
                <button
                  type="button"
                  className="btn ghost"
                  onClick={() => {
                    setAction(null);
                    setReason('');
                    setFile(null);
                  }}
                >
                  {t('inventory.vulndb.cancel')}
                </button>
              </div>
            </section>
          )}
          {notice !== null && <p className="hint ok">{t(notice)}</p>}
          <ul className="cards">
            <li className="card">
              <h4>{t('inventory.cards.open.title')}</h4>
              <div className="row">
                <span className="badge err">
                  {t('inventory.cards.open.components', { count: inventory.totals.vulnerable_components })}
                </span>
                <span className="badge warn">
                  {t('inventory.cards.open.projects', { count: inventory.projects.filter((p) => p.open_cves > 0).length })}
                </span>
              </div>
              <div className="meta">
                {t('inventory.cards.open.meta', {
                  critical: inventory.totals.by_severity['critical'] ?? 0,
                  high: inventory.totals.by_severity['high'] ?? 0,
                  medium: inventory.totals.by_severity['medium'] ?? 0,
                  low: inventory.totals.by_severity['low'] ?? 0,
                  notAffected: inventory.totals.not_affected,
                })}
              </div>
            </li>
            <li className="card">
              <h4>{t('inventory.cards.outdated.title')}</h4>
              <div className="row">
                <span className="badge warn">
                  {t('inventory.cards.outdated.count', {
                    outdated: inventory.totals.outdated,
                    total: inventory.totals.components,
                  })}
                </span>
              </div>
              <div className="progress">
                <div className="plabel">
                  <span>{t('inventory.cards.outdated.upToDate')}</span>
                  <span>{upToDate} %</span>
                </div>
                <div className="pbar">
                  <div className={`pfill ${widthClass(upToDate, 100)}`} />
                </div>
              </div>
              <div className="meta">{t('inventory.cards.outdated.meta')}</div>
            </li>
            <li className="card">
              <h4>{t('inventory.cards.licenses.title')}</h4>
              <div className="row">
                {inventory.licenses.map((license) => (
                  <span key={license.name} className="chip">
                    {license.name} {license.count}
                  </span>
                ))}
                {inventory.unlicensed > 0 && (
                  <span className="badge info">
                    {t('inventory.cards.licenses.unlicensed', { count: inventory.unlicensed })}
                  </span>
                )}
              </div>
              <div className="meta">
                {t('inventory.cards.licenses.cbom', {
                  algorithms: inventory.crypto.length,
                  weak: inventory.crypto_weak,
                })}
              </div>
            </li>
          </ul>
          <div className="cols inventory">
            <section className="panel">
              <h4>{t('inventory.byProject.title')}</h4>
              <p className="desc">{t('inventory.byProject.desc')}</p>
              {inventory.projects.length === 0 ? (
                <p className="hint">{t('inventory.byProject.none')}</p>
              ) : (
                <ul className="caselist">
                  {inventory.projects.map((row) => (
                    <ProjectRow
                      key={row.analysis_id}
                      row={row}
                      selected={row.analysis_id === selected}
                      onSelect={() => {
                        setSelected(row.analysis_id);
                      }}
                    />
                  ))}
                </ul>
              )}
              <div className="actions wrap">
                {DOCUMENTS.map((kind) => (
                  <button
                    key={kind}
                    type="button"
                    className={kind === 'sbom' ? 'btn primary' : 'btn ghost'}
                    disabled={selected === null}
                    onClick={() => void download(kind)}
                  >
                    {t(`inventory.download.${kind}`)}
                  </button>
                ))}
              </div>
            </section>
            <section className="panel">
              <div className="panelhead">
                <h4>{t('inventory.open.title')}</h4>
                <div className="radios" role="group" aria-label={t('inventory.open.filterLabel')}>
                  {(['all', 'high', 'unresolved'] as Filter[]).map((option) => (
                    <button
                      key={option}
                      type="button"
                      className={filter === option ? 'radio on' : 'radio'}
                      aria-pressed={filter === option}
                      onClick={() => {
                        setFilter(option);
                      }}
                    >
                      {t(`inventory.open.filter.${option}`)}
                    </button>
                  ))}
                </div>
              </div>
              {inventory.open.filter((row) => rowMatches(row, filter)).length === 0 ? (
                <p className="hint">{t('inventory.open.none')}</p>
              ) : (
                <ul className="caselist">
                  {inventory.open
                    .filter((row) => rowMatches(row, filter))
                    .map((row) => (
                      <OpenRow key={`${row.analysis_id}:${row.component}:${row.vulnerability_id}`} row={row} />
                    ))}
                </ul>
              )}
              {inventory.totals.uncomparable > 0 && (
                <p className="hint">
                  {t('inventory.open.uncomparable', { count: inventory.totals.uncomparable })}
                </p>
              )}
              <p className="hint">{t('inventory.open.hint')}</p>
              <h5>{t('inventory.crypto.title')}</h5>
              {inventory.crypto.length === 0 ? (
                <p className="hint">{t('inventory.crypto.none')}</p>
              ) : (
                <ul className="checks">
                  {inventory.crypto.map((row) => (
                    <li key={`${row.primitive}:${row.algorithm}`} className="checkline">
                      <span className={row.weak ? 'ck err' : 'ck done'} aria-hidden="true">
                        {row.weak ? '!' : '✓'}
                      </span>
                      <span className="mono">{row.algorithm}</span>
                      <span>
                        — {t(`inventory.crypto.primitive.${row.primitive}`, { defaultValue: row.primitive })}
                        {' · '}
                        <span className="mono">
                          {row.path}
                          {row.line !== null && `:${String(row.line)}`}
                        </span>
                        {row.occurrences > 1 && ` · ${t('inventory.crypto.more', { count: row.occurrences - 1 })}`}
                        {row.weak && (
                          <>
                            {' · '}
                            <b className="bad">{t('inventory.crypto.weak')}</b>
                          </>
                        )}
                      </span>
                    </li>
                  ))}
                </ul>
              )}
            </section>
          </div>
        </>
      )}
    </AppShell>
  );
}
