import type { FastifyInstance } from 'fastify';
import { buildAuthenticate, requireUser } from '../middleware/auth.js';
import { PLAN_QUOTAS } from '../auth/usage.js';
import { coverageSummary, type CoverageSummary } from '../coverage/ledger.js';
import { generatePdfReport } from '../reports/pdf.js';
import { generateDocxReport } from '../reports/docx.js';
import { generateMarkdownReport } from '../reports/markdown.js';
import { generateCsvReport } from '../reports/csv.js';
import { generateJsonReport } from '../reports/json.js';
import { fetchNvdScore, gradeFindings, isPublicTarget } from '../reports/gradeFindings.js';
import type { ScanRouteDeps } from './scans.js';

const FORMATS = ['pdf', 'docx', 'md', 'json', 'csv'] as const;
type ReportFormat = (typeof FORMATS)[number];

const CONTENT_TYPES: Record<ReportFormat, string> = {
  pdf: 'application/pdf',
  docx: 'application/vnd.openxmlformats-officedocument.wordprocessingml.document',
  md: 'text/markdown',
  json: 'application/json',
  csv: 'text/csv; charset=utf-8',
};

/**
 * Coverage summary for a scan, via the swarm task that ran it (the graph
 * task carries the scan id; the ledger is keyed by task). No task, no
 * stores, or any store failure means an empty summary: every class
 * untested, never clean. A coverage failure must not break the report.
 */
async function loadScanCoverage(
  deps: ScanRouteDeps,
  userId: string,
  scanId: string,
): Promise<CoverageSummary> {
  try {
    if (!deps.coverage || !deps.graph) return coverageSummary([]);
    const task = (await deps.graph.listTasks(userId)).find(
      (t) => t.scanId === scanId,
    );
    if (!task) return coverageSummary([]);
    return coverageSummary(await deps.coverage.listEntries(task.id));
  } catch {
    return coverageSummary([]);
  }
}

export async function reportRoutes(app: FastifyInstance, deps: ScanRouteDeps): Promise<void> {
  const { db } = deps;
  const authenticate = buildAuthenticate(db);

  app.get('/api/scans/:id/report', { preHandler: authenticate }, async (request, reply) => {
    const user = requireUser(request);
    const { id } = request.params as { id: string };
    const query = request.query as { format?: string };
    const format = (query.format ?? 'pdf') as ReportFormat;

    if (!FORMATS.includes(format)) {
      return reply.status(400).send({ error: `format must be one of: ${FORMATS.join(', ')}` });
    }
    if (!PLAN_QUOTAS[user.plan].reportFormats.includes(format)) {
      return reply
        .status(403)
        .send({ error: `The ${format.toUpperCase()} report format requires the Hunter plan or higher` });
    }

    const scan = await db.getScan(id);
    if (!scan || scan.userId !== user.id) {
      return reply.status(404).send({ error: 'Scan not found' });
    }
    if (scan.status !== 'completed') {
      return reply.status(409).send({ error: `Report is only available for completed scans (current: ${scan.status})` });
    }

    const findings = await gradeFindings(await db.listFindings(id), {
      context: { internetFacing: isPublicTarget(scan.targetUrl) },
      fetchNvdScore,
    });
    const coverage = await loadScanCoverage(deps, user.id, id);
    const input = { scan, findings, generatedBy: `BugSeek AI backend (${user.email})`, coverage };

    await db.recordUsage(user.id, 'report', 1, id);

    const filename = `bugseek-report-${id.slice(0, 8)}.${format}`;
    reply.header('content-type', CONTENT_TYPES[format]);
    reply.header('content-disposition', `attachment; filename="${filename}"`);

    switch (format) {
      case 'pdf':
        return reply.send(await generatePdfReport(input));
      case 'docx':
        return reply.send(await generateDocxReport(input));
      case 'md':
        return reply.send(generateMarkdownReport(input));
      case 'json':
        return reply.send(generateJsonReport(input));
      case 'csv':
        return reply.send(generateCsvReport(input));
    }
  });
}
