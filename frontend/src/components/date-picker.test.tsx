/** The calendar picker: ISO out, locale in, never a future day. */
import es from '../locales/es.json';
import { render, screen } from '@testing-library/react';
import userEvent from '@testing-library/user-event';
import { useState } from 'react';
import { describe, expect, it } from 'vitest';

import { DatePicker } from './date-picker';

function Harness({ initial = '', max }: { initial?: string; max?: string }) {
  const [value, setValue] = useState(initial);
  return (
    <>
      <label htmlFor="d">Fecha</label>
      <DatePicker id="d" value={value} onChange={setValue} max={max} />
      <output data-testid="iso">{value}</output>
    </>
  );
}

describe('date picker', () => {
  it('opens on the selected month and hands over ISO when a day is picked', async () => {
    render(<Harness initial="2024-03-05" />);
    const user = userEvent.setup();
    const field = screen.getByLabelText('Fecha');
    expect(field).toHaveTextContent('5 de marzo de 2024');

    await user.click(field);
    const dialog = screen.getByRole('dialog', { name: es.datePicker.dialog });
    expect(dialog).toHaveTextContent('marzo de 2024');
    expect(screen.getByRole('button', { name: 'martes, 5 de marzo de 2024' })).toHaveAttribute('aria-pressed', 'true');

    await user.click(screen.getByRole('button', { name: 'lunes, 18 de marzo de 2024' }));
    expect(screen.getByTestId('iso')).toHaveTextContent('2024-03-18');
    expect(screen.queryByRole('dialog')).toBeNull();
    expect(field).toHaveTextContent('18 de marzo de 2024');
  });

  it('navigates months, refuses days after max and clears', async () => {
    render(<Harness initial="2024-03-05" max="2024-03-10" />);
    const user = userEvent.setup();
    await user.click(screen.getByLabelText('Fecha'));

    expect(screen.getByRole('button', { name: 'lunes, 11 de marzo de 2024' })).toBeDisabled();
    expect(screen.getByRole('button', { name: 'domingo, 10 de marzo de 2024' })).toBeEnabled();

    await user.click(screen.getByRole('button', { name: es.datePicker.prevMonth }));
    expect(screen.getByRole('dialog')).toHaveTextContent('febrero de 2024');
    await user.click(screen.getByRole('button', { name: es.datePicker.nextMonth }));
    await user.click(screen.getByRole('button', { name: es.datePicker.nextMonth }));
    expect(screen.getByRole('dialog')).toHaveTextContent('abril de 2024');
    // Every day of April is after max.
    expect(screen.getByRole('button', { name: 'lunes, 1 de abril de 2024' })).toBeDisabled();

    await user.click(screen.getByRole('button', { name: es.datePicker.clear }));
    expect(screen.getByTestId('iso')).toHaveTextContent('');
    expect(screen.getByLabelText('Fecha')).toHaveTextContent(es.datePicker.placeholder);
  });

  it('is driven by the keyboard: arrows move, Enter picks, Escape closes', async () => {
    render(<Harness initial="2024-03-05" />);
    const user = userEvent.setup();
    await user.click(screen.getByLabelText('Fecha'));
    // Focus lands on the selected day; one week down and one day right = 13 March.
    await user.keyboard('{ArrowDown}{ArrowRight}{Enter}');
    expect(screen.getByTestId('iso')).toHaveTextContent('2024-03-13');

    await user.click(screen.getByLabelText('Fecha'));
    await user.keyboard('{Escape}');
    expect(screen.queryByRole('dialog')).toBeNull();
    expect(screen.getByTestId('iso')).toHaveTextContent('2024-03-13');
  });
});
