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
    // Mirrors backend/app/auth/errors.py + app/core/errors.py + app/ingest/errors.py
    // + app/analysis/{normalizer,sbom}.py + app/reports/errors.py + app/workflow/errors.py
    // + app/workflow/ast/errors.py + app/inventory/errors.py.
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
      'errors.ingest.failed',
      'errors.ingest.zipSlip',
      'errors.ingest.zipTooLarge',
      'errors.ingest.tooManyEntries',
      'errors.ingest.zipBomb',
      'errors.ingest.invalidArchive',
      'errors.ingest.forbiddenHost',
      'errors.ingest.invalidUrl',
      'errors.ingest.repoUnreachable',
      'errors.projects.notFound',
      'errors.projects.installedAtInFuture',
      'errors.analysis.notFound',
      'errors.analysis.notReady',
      'errors.analysis.normalization',
      'errors.analysis.noToolRan',
      'errors.analysis.sbomInvalid',
      'errors.report.renderFailed',
      'errors.report.versionNotFound',
      'errors.report.versionNotCurrent',
      'errors.report.versionAlreadySigned',
      'errors.report.unknownSection',
      'errors.report.sectionTooLong',
      'errors.findings.notFound',
      'errors.workflow.findingNotTriageable',
      'errors.workflow.failed',
      'errors.workflow.justificationRequired',
      'errors.workflow.stageFinal',
      'errors.workflow.stageLocked',
      'errors.workflow.stageNotReached',
      'errors.workflow.testPlanNotFound',
      'errors.workflow.testPlanEmpty',
      'errors.workflow.testPlanFunctionUnknown',
      'errors.workflow.gate.closed',
      'errors.workflow.gate.analysisNotDone',
      'errors.workflow.gate.triagePending',
      'errors.workflow.gate.testPlanMissing',
      'errors.workflow.gate.notBuilt',
      'errors.workflow.gate.casesNotApproved',
      'errors.workflow.caseItemUnknown',
      'errors.workflow.casesInvalid',
      'errors.workflow.briefNotCovered',
      'errors.workflow.casesTooFew',
      'errors.workflow.designNotApproved',
      'errors.workflow.testsUnparsable',
      'errors.workflow.testsTooLarge',
      'errors.workflow.gate.testsNotWritten',
      'errors.workflow.gate.notVerified',
      'errors.workflow.gate.verificationFailed',
      'errors.workflow.mutantUnknown',
      'errors.sandbox.failed',
      'errors.sandbox.unavailable',
      'errors.sandbox.timeout',
      'errors.sandbox.resultsUnreadable',
      'errors.workflow.testPlanFunctionUnbriefable',
      'errors.workflow.testPlanFunctionTooComplex',
      'errors.ast.failed',
      'errors.ast.unsupportedLanguage',
      'errors.ast.sourceTooLarge',
      'errors.ast.functionNotFound',
      'errors.ast.parseFailed',
      'errors.ast.tooDeep',
      'errors.ast.functionNotInPlan',
      'errors.inventory.failed',
      'errors.inventory.dumpTooLarge',
      'errors.inventory.dumpInvalid',
      'errors.inventory.dumpKindUnknown',
      'errors.inventory.syncDisabled',
      'errors.inventory.sbomMissing',
      'errors.inventory.downloadFailed',
      'errors.inventory.enqueueFailed',
    ];
    expect(spanish).toEqual(expect.arrayContaining(backendKeys));
  });
});
