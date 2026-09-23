/**
 * Projects list + stage E1 registration form.
 * Mockup anchors: screen 02 (cards) and screen 03 "1 · Datos del sistema".
 */
import { useEffect, useId, useState, type FormEvent } from 'react';
import { useTranslation } from 'react-i18next';

import { ApiError } from '../api/client';
import * as api from '../api/projects';
import type { Analysis, Project } from '../api/projects';
import { useAuth } from '../auth/auth-context';
import { AppShell } from '../components/app-shell';
import { DatePicker } from '../components/date-picker';
import { StatusBadge } from '../components/status-badge';
import type { Route } from '../navigation/use-route';

interface Props {
  route: Route;
  onNavigate: (route: Route) => void;
}

/** Today, ISO, from LOCAL calendar parts: an installation cannot be in the future. */
function todayIso(): string {
  const now = new Date();
  return `${String(now.getFullYear())}-${String(now.getMonth() + 1).padStart(2, '0')}-${String(now.getDate()).padStart(2, '0')}`;
}

function Field({
  id,
  label,
  value,
  onChange,
  required,
}: {
  id: string;
  label: string;
  value: string;
  onChange: (value: string) => void;
  required?: boolean;
}): React.ReactNode {
  return (
    <div className="field">
      <label htmlFor={id}>{label}</label>
      <input
        id={id}
        className="input"
        value={value}
        required={required}
        maxLength={200}
        onChange={(event) => {
          onChange(event.target.value);
        }}
      />
    </div>
  );
}

function RegisterForm({
  onCreated,
  onCancel,
}: {
  onCreated: (project: Project) => void;
  onCancel: () => void;
}): React.ReactNode {
  const { t } = useTranslation();
  const { accessToken } = useAuth();
  const ids = {
    name: useId(),
    description: useId(),
    systemName: useId(),
    framework: useId(),
    database: useId(),
    developer: useId(),
    installedAt: useId(),
  };
  const [name, setName] = useState('');
  const [description, setDescription] = useState('');
  const [systemName, setSystemName] = useState('');
  const [framework, setFramework] = useState('');
  const [database, setDatabase] = useState('');
  const [developer, setDeveloper] = useState('');
  const [installedAt, setInstalledAt] = useState('');
  const [errorKey, setErrorKey] = useState<string | null>(null);
  const [submitting, setSubmitting] = useState(false);

  const optional = (value: string): string | undefined =>
    value.trim() === '' ? undefined : value.trim();

  async function handleSubmit(event: FormEvent<HTMLFormElement>): Promise<void> {
    event.preventDefault();
    if (accessToken === null) return;
    setErrorKey(null);
    setSubmitting(true);
    try {
      const project = await api.createProject(accessToken, {
        name: name.trim(),
        description: optional(description),
        system: {
          name: systemName.trim(),
          framework: optional(framework),
          database: optional(database),
          developer: optional(developer),
          installed_at: optional(installedAt),
        },
      });
      onCreated(project);
    } catch (error) {
      setErrorKey(error instanceof ApiError ? error.messageKey : 'errors.internal');
    } finally {
      setSubmitting(false);
    }
  }

  return (
    <form className="panel" onSubmit={(event) => void handleSubmit(event)} noValidate>
      <h5>{t('projects.form.section')}</h5>
      <p className="desc">{t('projects.form.intro')}</p>
      {errorKey !== null && (
        <p className="alert" role="alert">
          {t(errorKey)}
        </p>
      )}
      <div className="cols two">
        <Field id={ids.name} label={t('projects.form.name')} value={name} onChange={setName} required />
        <Field
          id={ids.systemName}
          label={t('projects.form.systemName')}
          value={systemName}
          onChange={setSystemName}
          required
        />
        <Field id={ids.framework} label={t('projects.form.framework')} value={framework} onChange={setFramework} />
        <Field id={ids.database} label={t('projects.form.database')} value={database} onChange={setDatabase} />
        <Field id={ids.developer} label={t('projects.form.developer')} value={developer} onChange={setDeveloper} />
        <div className="field">
          <label id={`${ids.installedAt}-label`} htmlFor={ids.installedAt}>
            {t('projects.form.installedAt')}
          </label>
          <DatePicker
            id={ids.installedAt}
            labelledBy={`${ids.installedAt}-label`}
            value={installedAt}
            onChange={setInstalledAt}
            max={todayIso()}
          />
        </div>
      </div>
      <Field id={ids.description} label={t('projects.form.description')} value={description} onChange={setDescription} />
      <div className="actions">
        <button type="submit" className="btn primary" disabled={submitting}>
          {submitting ? t('projects.form.submitting') : t('projects.form.submit')}
        </button>
        <button type="button" className="btn ghost" onClick={onCancel}>
          {t('projects.form.cancel')}
        </button>
        <span className="hint">{t('projects.form.hint')}</span>
      </div>
    </form>
  );
}

export function ProjectsScreen({ route, onNavigate }: Props): React.ReactNode {
  const { t, i18n } = useTranslation();
  const { user, accessToken } = useAuth();
  const [projects, setProjects] = useState<Project[] | null>(null);
  const [latest, setLatest] = useState<Record<string, Analysis | undefined>>({});
  const [errorKey, setErrorKey] = useState<string | null>(null);
  const [registering, setRegistering] = useState(false);

  const canRegister = user?.role === 'admin' || user?.role === 'analyst';

  useEffect(() => {
    if (accessToken === null) return;
    let cancelled = false;
    api
      .listProjects(accessToken)
      .then(async (list) => {
        if (cancelled) return;
        setProjects(list);
        const entries = await Promise.all(
          list.map(async (project) => {
            const analyses = await api.listAnalyses(accessToken, project.id).catch(() => []);
            return [project.id, analyses[0]] as const;
          }),
        );
        if (!cancelled) setLatest(Object.fromEntries(entries));
      })
      .catch((error: unknown) => {
        if (!cancelled) {
          setErrorKey(error instanceof ApiError ? error.messageKey : 'errors.internal');
        }
      });
    return () => {
      cancelled = true;
    };
  }, [accessToken]);

  const formatDate = (iso: string): string =>
    new Date(iso).toLocaleDateString(i18n.resolvedLanguage, { dateStyle: 'medium' });

  return (
    <AppShell route={route} onNavigate={onNavigate}>
      <div className="pagehead">
        <h2>{t('projects.title')}</h2>
        <p className="sub">{t('projects.subtitle')}</p>
      </div>

      {registering ? (
        <RegisterForm
          onCancel={() => {
            setRegistering(false);
          }}
          onCreated={(project) => {
            onNavigate({ kind: 'project', id: project.id });
          }}
        />
      ) : (
        <section className="nextstep">
          <div className="txt">
            <b>{t('projects.nextStepTitle')}</b>
            <div>{canRegister ? t('projects.nextStepBody') : t('projects.nextStepBodyDeveloper')}</div>
          </div>
          {canRegister && (
            <button
              type="button"
              className="btn primary"
              onClick={() => {
                setRegistering(true);
              }}
            >
              {t('projects.register')}
            </button>
          )}
        </section>
      )}

      {errorKey !== null && (
        <p className="alert" role="alert">
          {t(errorKey)}
        </p>
      )}

      {projects !== null && projects.length === 0 && !registering && (
        <p className="hint">{t('projects.empty')}</p>
      )}

      {projects !== null && projects.length > 0 && (
        <ul className="cards" aria-label={t('projects.listLabel')}>
          {projects.map((project) => {
            const analysis = latest[project.id];
            return (
              <li key={project.id} className="card">
                <h4>
                  <a
                    href={`#/projects/${project.id}`}
                    onClick={(event) => {
                      event.preventDefault();
                      onNavigate({ kind: 'project', id: project.id });
                    }}
                  >
                    {project.name}
                  </a>
                </h4>
                <div className="sub">{project.system?.name ?? ''}</div>
                <div className="row">
                  {project.system?.framework && <span className="chip">{project.system.framework}</span>}
                  {analysis ? (
                    <StatusBadge status={analysis.status} />
                  ) : (
                    <span className="badge info">{t('projects.noAnalysis')}</span>
                  )}
                </div>
                <div className="meta">
                  {t('projects.createdAt', { date: formatDate(project.created_at) })}
                </div>
              </li>
            );
          })}
        </ul>
      )}
    </AppShell>
  );
}
