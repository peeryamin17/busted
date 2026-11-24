import { test } from 'node:test';
import assert from 'node:assert/strict';
import { reportDownloadError, reportFilename, reportUrl } from './reportDownload.ts';

test('reportUrl builds the scan report URL', () => {
  assert.equal(reportUrl('abc123', 'pdf'), '/api/scans/abc123/report?format=pdf');
  assert.equal(reportUrl('a/b', 'md'), '/api/scans/a%2Fb/report?format=md');
});

test('reportDownloadError prefers the backend message when present', () => {
  assert.equal(
    reportDownloadError(403, 'The PDF report format requires the Hunter plan or higher'),
    'The PDF report format requires the Hunter plan or higher',
  );
  assert.equal(
    reportDownloadError(409, 'Report is only available for completed scans (current: running)'),
    'Report is only available for completed scans (current: running)',
  );
  assert.equal(reportDownloadError(404, 'Scan not found'), 'Scan not found');
});

test('reportDownloadError falls back per status without a backend message', () => {
  assert.equal(reportDownloadError(401), 'Sign in again to download this report.');
  assert.equal(reportDownloadError(403), 'This report format needs the Hunter plan or higher.');
  assert.equal(reportDownloadError(404), 'That report is no longer available.');
  assert.equal(reportDownloadError(409), 'This report is only available once the scan has finished.');
  assert.equal(reportDownloadError(500), 'Download failed (500).');
});

test('reportFilename reads the backend content-disposition and falls back otherwise', () => {
  assert.equal(
    reportFilename('attachment; filename="bugseek-report-abc12345.pdf"', 'abc12345', 'pdf'),
    'bugseek-report-abc12345.pdf',
  );
  assert.equal(reportFilename('attachment; filename=report.md', 'abc12345', 'md'), 'report.md');
  assert.equal(reportFilename(null, 'abc12345', 'json'), 'bugseek-report-abc12345.json');
  assert.equal(reportFilename('attachment', 'abc12345', 'docx'), 'bugseek-report-abc12345.docx');
});
