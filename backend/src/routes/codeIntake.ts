import type { FastifyInstance } from 'fastify';
import { z } from 'zod';
import { buildAuthenticate, requireUser } from '../middleware/auth.js';
import { redactFindingEvidence } from '../guardrails/redact.js';
import { estimateCvss } from '../reports/cvss.js';
import { securityScore } from '../reports/score.js';
import type { RouteDeps } from './health.js';
import {
  analyzeCodeArchive,
  MAX_ARCHIVE_BYTES,
  type CodeIntakeFinding,
} from '../codeIntake/analyzer.js';
import type { Confidence, Severity } from '../types.js';

/**
 * Code-intake route (white-box, Thread 3).
 *
 *   POST /api/code-intake?kind=zip|jar&filename=<name>
 *
 * Uploads a code archive as a raw binary body (application/zip,
 * application/java-archive, or application/octet-stream, no multipart
 * dependency; the body IS the archive). Authenticated users only; no plan
 * gate and no credit charge, static analysis of the user's own code.
 *
 * Limits: 10 MB archive, 2, 000 entries, 2 MB per file. Analysis runs
 * in memory; nothing is written to disk. Results are persisted as a scan
 * with category 'whitebox' findings so the report builders render them
 * in the dedicated White-box section.
 */

const querySchema = z.object({
  kind: z.enum(['zip', 'jar']).default('zip'),
  filename: z
    .string()
    .min(1)
    .max(200)
    .regex(/^[^/\\]+$/, 'filename must be a plain file name')
    .default('upload.zip'),
});

type Db = RouteDeps['db'];

const ZIP_MAGIC = [0x50, 0x4b, 0x03, 0x04]; // PK\x03\x04
const EMPTY_ZIP_MAGIC = [0x50, 0x4b, 0x05, 0x06]; // PK\x05\x06 (empty archive)

function isZipBuffer(buf: Buffer): boolean {
  return (
    ZIP_MAGIC.every((b, i) => buf[i] === b) ||
    EMPTY_ZIP_MAGIC.every((b, i) => buf[i] === b)
  );
}

export async function codeIntakeRoutes(app: FastifyInstance, deps: RouteDeps): Promise<void> {
  const { db } = deps;
  const authenticate = buildAuthenticate(db);

  // Raw binary body parsers, the request body IS the archive.
  for (const contentType of ['application/zip', 'application/java-archive', 'application/octet-stream']) {
    app.addContentTypeParser(contentType, { parseAs: 'buffer' }, (_req, body, done) => {
      done(null, body);
    });
  }

  app.post(
    '/api/code-intake',
    {
      preHandler: authenticate,
      bodyLimit: MAX_ARCHIVE_BYTES,
    },
    async (request, reply) => {
      const user = requireUser(request);
      const query = querySchema.safeParse(request.query);
      if (!query.success) {
        return reply.status(400).send({ error: query.error.issues[0]?.message ?? 'Invalid query' });
      }
      const { kind, filename } = query.data;

      const body = request.body as Buffer | undefined;
      if (!body || !Buffer.isBuffer(body) || body.length === 0) {
        return reply.status(400).send({
          error: 'Send the archive as the raw request body (Content-Type: application/zip or application/java-archive)',
        });
      }
      if (body.length > MAX_ARCHIVE_BYTES) {
        return reply.status(413).send({ error: `Archive exceeds the 10 MB limit (${Math.round(body.length / 1024 / 1024)} MB received)` });
      }
      if (!isZipBuffer(body)) {
        return reply.status(400).send({ error: 'Upload is not a ZIP archive (JAR/WAR files are ZIP archives too)' });
      }

      let result;
      try {
        result = await analyzeCodeArchive(body, kind, filename);
      } catch (err) {
        return reply.status(400).send({ error: `Could not analyse archive: ${(err as Error).message}` });
      }

      const scan = await db.createScan({
        userId: user.id,
        targetUrl: `code-intake:${filename}`,
        mode: 'passive',
        scope: { mode: 'page', includeSubdomains: false, excludedHosts: [], excludedPaths: [], maxRequestsPerSecond: 1 },
        techStack: [],
      });

      const persisted = await db.addFindings(
        result.findings.map((f: CodeIntakeFinding) => {
          const cvss = estimateCvss(f.severity as Severity, f.category);
          return redactFindingEvidence({
            scanId: scan.id,
            category: f.category,
            title: f.title,
            description: `${f.description}\n\nMethod: ${result.method}`,
            severity: f.severity as Severity,
            confidence: f.confidence as Confidence,
            cvssScore: cvss.score,
            cvssVector: cvss.vector,
            trapProbability: 0,
            honeypotSuspect: false,
            location: f.location,
            evidence: f.evidence,
            reproSteps: [],
            remediation: f.remediation,
            references: f.references,
          });
        }),
      );
      await db.updateScan(scan.id, { status: 'completed' });

      return reply.send({
        scanId: scan.id,
        kind: result.kind,
        filename,
        method: result.method,
        filesScanned: result.filesScanned,
        entriesSkipped: result.entriesSkipped,
        warnings: result.warnings,
        findings: persisted.map((f) => ({
          id: f.id,
          category: f.category,
          title: f.title,
          description: f.description,
          severity: f.severity,
          confidence: f.confidence,
          location: f.location,
          evidence: f.evidence,
          remediation: f.remediation,
          cvssScore: f.cvssScore,
          cvssVector: f.cvssVector,
        })),
        score: securityScore(
          result.findings.map((f) => ({ severity: f.severity, confidence: f.confidence, honeypotSuspect: false })),
        ),
      });
    },
  );
}
