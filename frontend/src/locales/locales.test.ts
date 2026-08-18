/**
 * Locale parity. A missing translation is a bug, not a fallback: the UI must
 * never show a Spanish string to someone who chose English.
 */
import { describe, expect, it } from 'vitest';

import en from './en.json';
import es from './es.json';

type Tree = { [key: string]: string | Tree };

function flattenEntries(tree: Tree, prefix = ''): [string, string][] {
  return Object.entries(tree).flatMap<[string, string]>(([key, value]) => {
    const path = prefix === '' ? key : `${prefix}.${key}`;
    return typeof value === 'string' ? [[path, value]] : flattenEntries(value, path);
  });
}

function flatten(tree: Tree, prefix = ''): string[] {
  return flattenEntries(tree, prefix).map(([path]) => path);
}

describe('locale files', () => {
  const spanish = flatten(es as Tree).sort();
  const english = flatten(en as Tree).sort();

  it('declare exactly the same keys', () => {
    expect(english).toEqual(spanish);
  });

  it('leave no value empty', () => {
    // Assert on VALUES, not key paths: a path is never empty, so checking the
    // output of flatten() here would be a tautology that ships blank strings.
    const entries = [...flattenEntries(es as Tree), ...flattenEntries(en as Tree)];
    const empty = entries.filter(([, value]) => value.trim().length === 0).map(([path]) => path);
    expect(empty).toEqual([]);
  });

  it('cover every error key the backend can return', () => {
    // Mirrors backend/app/auth/errors.py + app/core/errors.py.
    const backendKeys = [
      'errors.internal',
      'errors.validation',
      'errors.auth.invalidCredentials',
      'errors.auth.accountLocked',
      'errors.auth.accountDisabled',
      'errors.auth.invalidToken',
      'errors.auth.sessionRevoked',
      'errors.auth.passwordChangeRequired',
      'errors.auth.weakPassword',
      'errors.auth.invalidUsername',
      'errors.auth.forbidden',
    ];
    expect(spanish).toEqual(expect.arrayContaining(backendKeys));
  });
});
