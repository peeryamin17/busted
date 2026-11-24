import { test } from 'node:test';
import assert from 'node:assert/strict';
import {
  formatApprovalsLoadError,
  formatBatchDecisionNote,
  formatDecisionNote,
} from './approvals.ts';

test('formatApprovalsLoadError names the HTTP status', () => {
  assert.match(formatApprovalsLoadError(401), /401/);
  assert.match(formatApprovalsLoadError(500), /500/);
  assert.notEqual(formatApprovalsLoadError(401), formatApprovalsLoadError(500));
});

test('formatApprovalsLoadError reports a network error without a status', () => {
  assert.match(formatApprovalsLoadError(null), /network error/i);
  assert.doesNotMatch(formatApprovalsLoadError(null), /HTTP/);
});

test('formatDecisionNote states the saved decision', () => {
  assert.match(formatDecisionNote('allow', 'Run nmap scan'), /Allowed/);
  assert.match(formatDecisionNote('deny', 'Run nmap scan'), /Denied/);
  assert.match(formatDecisionNote('allow', 'Run nmap scan'), /Run nmap scan/);
});

test('formatDecisionNote trims a long action', () => {
  const note = formatDecisionNote('allow', 'x'.repeat(200));
  assert.ok(note.length < 200);
});

test('formatBatchDecisionNote counts saved steps', () => {
  assert.match(formatBatchDecisionNote('allow', 3, 3), /3 steps/);
  assert.match(formatBatchDecisionNote('deny', 1, 3), /1 of 3/);
});
