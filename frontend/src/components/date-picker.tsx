/**
 * A calendar date picker: one field that opens a month grid.
 *
 * The value is ALWAYS ISO `YYYY-MM-DD` built from local calendar parts (never
 * through `Date.toISOString`, which would shift a day near midnight), and it
 * is only ever displayed formatted for the UI locale. Nothing is bundled: the
 * month and weekday names come from `Intl`, so both languages are covered by
 * the browser. Weeks start on Monday, as in the institution's calendar.
 */
import { useEffect, useId, useRef, useState, type KeyboardEvent } from 'react';
import { useTranslation } from 'react-i18next';

interface Props {
  id: string;
  /** ISO `YYYY-MM-DD`, or '' when unset. */
  value: string;
  onChange: (iso: string) => void;
  /** Latest selectable day, ISO. */
  max?: string;
  /** Id of the field's own `<label>`; both it and the chosen date are announced. */
  labelledBy?: string;
}

interface Day {
  year: number;
  month: number; // 0-based
  day: number;
}

function toIso({ year, month, day }: Day): string {
  return `${String(year)}-${String(month + 1).padStart(2, '0')}-${String(day).padStart(2, '0')}`;
}

function fromIso(iso: string): Day | null {
  const match = /^(\d{4})-(\d{2})-(\d{2})$/.exec(iso);
  if (match === null) return null;
  const year = Number(match[1]);
  const month = Number(match[2]) - 1;
  const day = Number(match[3]);
  const probe = new Date(year, month, day);
  if (probe.getFullYear() !== year || probe.getMonth() !== month || probe.getDate() !== day) return null;
  return { year, month, day };
}

function todayParts(): Day {
  const now = new Date();
  return { year: now.getFullYear(), month: now.getMonth(), day: now.getDate() };
}

/** The 42 cells (6 weeks, Monday first) that show `year`/`month`. */
function monthCells(year: number, month: number): Day[] {
  const first = new Date(year, month, 1);
  const lead = (first.getDay() + 6) % 7; // Monday = 0
  const cells: Day[] = [];
  for (let offset = -lead; cells.length < 42; offset += 1) {
    const date = new Date(year, month, 1 + offset);
    cells.push({ year: date.getFullYear(), month: date.getMonth(), day: date.getDate() });
  }
  return cells;
}

function shift(day: Day, days: number): Day {
  const date = new Date(day.year, day.month, day.day + days);
  return { year: date.getFullYear(), month: date.getMonth(), day: date.getDate() };
}

/** A calendar page. Stroke follows `currentColor`; drawn, never a font glyph. */
function CalendarGlyph(): React.ReactNode {
  return (
    <svg
      className="date-glyph"
      viewBox="0 0 24 24"
      width="16"
      height="16"
      fill="none"
      stroke="currentColor"
      strokeWidth="1.8"
      strokeLinecap="round"
      strokeLinejoin="round"
      aria-hidden="true"
      focusable="false"
    >
      <rect x="3" y="5" width="18" height="16" rx="2" />
      <path d="M3 10h18M8 3v4M16 3v4" />
    </svg>
  );
}

export function DatePicker({
  id,
  value,
  onChange,
  max,
  labelledBy,
}: Props): React.ReactNode {
  const { t, i18n } = useTranslation();
  const locale = i18n.resolvedLanguage ?? 'es';
  const dialogId = useId();
  const rootRef = useRef<HTMLDivElement>(null);
  const gridRef = useRef<HTMLDivElement>(null);
  const [open, setOpen] = useState(false);
  const selected = fromIso(value);
  const today = todayParts();
  // The month on screen and the day that holds keyboard focus inside the grid.
  const [cursor, setCursor] = useState<Day>(selected ?? today);

  useEffect(() => {
    if (!open) return;
    const close = (event: MouseEvent) => {
      if (rootRef.current !== null && !rootRef.current.contains(event.target as Node)) setOpen(false);
    };
    document.addEventListener('mousedown', close);
    return () => {
      document.removeEventListener('mousedown', close);
    };
  }, [open]);

  useEffect(() => {
    if (!open) return;
    // Keyboard users land on the focused day, never on a detached popover.
    gridRef.current?.querySelector<HTMLButtonElement>('button[tabindex="0"]')?.focus();
  }, [open, cursor]);

  const isDisabled = (day: Day): boolean => max !== undefined && toIso(day) > max;
  const monthTitle = new Intl.DateTimeFormat(locale, { month: 'long', year: 'numeric' }).format(
    new Date(cursor.year, cursor.month, 1),
  );
  const weekdayNames = monthCells(2024, 0)
    .slice(0, 7)
    .map((day) => new Intl.DateTimeFormat(locale, { weekday: 'short' }).format(new Date(day.year, day.month, day.day)));
  const shown = selected === null ? '' : new Intl.DateTimeFormat(locale, { dateStyle: 'long' }).format(new Date(selected.year, selected.month, selected.day));

  function openAt(day: Day): void {
    setCursor(day);
    setOpen(true);
  }

  function pick(day: Day): void {
    if (isDisabled(day)) return;
    onChange(toIso(day));
    setOpen(false);
  }

  function onGridKey(event: KeyboardEvent<HTMLDivElement>): void {
    const moves: Record<string, number> = { ArrowLeft: -1, ArrowRight: 1, ArrowUp: -7, ArrowDown: 7 };
    if (event.key in moves) {
      event.preventDefault();
      setCursor(shift(cursor, moves[event.key] ?? 0));
    } else if (event.key === 'PageUp' || event.key === 'PageDown') {
      event.preventDefault();
      const date = new Date(cursor.year, cursor.month + (event.key === 'PageUp' ? -1 : 1), cursor.day);
      setCursor({ year: date.getFullYear(), month: date.getMonth(), day: date.getDate() });
    } else if (event.key === 'Enter' || event.key === ' ') {
      event.preventDefault();
      pick(cursor);
    } else if (event.key === 'Escape') {
      event.preventDefault();
      setOpen(false);
    }
  }

  return (
    <div className="datepicker" ref={rootRef}>
      <button
        type="button"
        id={id}
        className={shown === '' ? 'input datefield empty' : 'input datefield'}
        aria-haspopup="dialog"
        // The label alone would win the accessible name and the chosen date
        // would never be read; naming both makes the field announce
        // "Fecha de instalación, 5 de marzo de 2024".
        aria-labelledby={labelledBy === undefined ? undefined : `${labelledBy} ${id}`}
        aria-expanded={open}
        aria-controls={open ? dialogId : undefined}
        onClick={() => {
          if (open) setOpen(false);
          else openAt(selected ?? today);
        }}
      >
        <span>{shown === '' ? t('datePicker.placeholder') : shown}</span>
        <span className="glyph">
          <CalendarGlyph />
        </span>
      </button>
      {open && (
        <div
          id={dialogId}
          className="datepop"
          role="dialog"
          aria-label={t('datePicker.dialog')}
          onKeyDown={(event) => {
            if (event.key === 'Escape') {
              setOpen(false);
              document.getElementById(id)?.focus();
            }
          }}
        >
          <div className="head">
            <button
              type="button"
              className="btn ghost small"
              aria-label={t('datePicker.prevMonth')}
              title={t('datePicker.prevMonth')}
              onClick={() => {
                setCursor({ ...cursor, month: cursor.month - 1, day: 1 });
              }}
            >
              ‹
            </button>
            <span className="month" aria-live="polite">
              {monthTitle}
            </span>
            <button
              type="button"
              className="btn ghost small"
              aria-label={t('datePicker.nextMonth')}
              title={t('datePicker.nextMonth')}
              onClick={() => {
                setCursor({ ...cursor, month: cursor.month + 1, day: 1 });
              }}
            >
              ›
            </button>
          </div>
          {/*
            * Deliberately NOT role="grid": that contract requires role="row"
            * owners, and role="gridcell" on a <button> replaces the button role,
            * so "activatable" stops being announced. Plain buttons in a labelled
            * group say the truth, and the keyboard handling below is ours either
            * way.
            */}
          <div
            className="dategrid"
            role="group"
            aria-label={monthTitle}
            ref={gridRef}
            onKeyDown={onGridKey}
          >
            {weekdayNames.map((name) => (
              <span key={name} className="wd" aria-hidden="true">
                {name}
              </span>
            ))}
            {monthCells(cursor.year, cursor.month).map((cell) => {
              const iso = toIso(cell);
              const isSel = selected !== null && toIso(selected) === iso;
              const isToday = toIso(today) === iso;
              const isCursor = toIso(cursor) === iso;
              const classes = [
                'day',
                cell.month !== cursor.month ? 'out' : '',
                isSel ? 'sel' : '',
                isToday ? 'today' : '',
              ]
                .filter(Boolean)
                .join(' ');
              return (
                <button
                  key={iso}
                  type="button"
                  className={classes}
                  tabIndex={isCursor ? 0 : -1}
                  aria-pressed={isSel}
                  aria-current={isToday ? 'date' : undefined}
                  aria-label={new Intl.DateTimeFormat(locale, { dateStyle: 'full' }).format(
                    new Date(cell.year, cell.month, cell.day),
                  )}
                  disabled={isDisabled(cell)}
                  onClick={() => {
                    pick(cell);
                  }}
                >
                  {cell.day}
                </button>
              );
            })}
          </div>
          <div className="foot">
            <button
              type="button"
              className="btn ghost small"
              disabled={isDisabled(today)}
              onClick={() => {
                pick(today);
              }}
            >
              {t('datePicker.today')}
            </button>
            <button
              type="button"
              className="btn ghost small"
              onClick={() => {
                onChange('');
                setOpen(false);
              }}
            >
              {t('datePicker.clear')}
            </button>
          </div>
        </div>
      )}
    </div>
  );
}
