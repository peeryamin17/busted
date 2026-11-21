import type { Pool } from 'pg';

export interface SwarmJobRow {
  id: string;
  user_id: string;
  target_origin: string;
  status: 'queued' | 'running' | 'validating' | 'completed' | 'failed';
  auth_source: 'byok' | 'platform_credits' | 'operator';
  surface_snapshot: Record<string, unknown>;
}

export class PgSwarmQueue {
  constructor(private readonly pool: Pool) {}

  async enqueue(params: {
    userId: string;
    targetOrigin: string;
    authSource: 'byok' | 'platform_credits' | 'operator';
    surfaceSnapshot: Record<string, unknown>;
  }): Promise<string> {
    const { rows } = await this.pool.query<{ id: string }>(
      `INSERT INTO swarm_jobs (user_id, target_origin, status, auth_source, surface_snapshot)
       VALUES ($1, $2, 'queued', $3, $4::jsonb)
       RETURNING id`,
      [
        params.userId,
        params.targetOrigin,
        params.authSource,
        JSON.stringify(params.surfaceSnapshot),
      ]
    );
    return rows[0].id;
  }

  // Atomically claim the next queued job (or recover a job stuck > 15m after a crash)
  async claimNext(): Promise<SwarmJobRow | null> {
    const client = await this.pool.connect();
    try {
      await client.query('BEGIN');
      const { rows } = await client.query<SwarmJobRow>(
        `SELECT id, user_id, target_origin, status, auth_source, surface_snapshot
         FROM swarm_jobs
         WHERE status = 'queued'
            OR (status IN ('running', 'validating') AND updated_at < NOW() - INTERVAL '15 minutes')
         ORDER BY created_at ASC
         LIMIT 1
         FOR UPDATE SKIP LOCKED`
      );

      if (rows.length === 0) {
        await client.query('COMMIT');
        return null;
      }

      const job = rows[0];
      await client.query(
        `UPDATE swarm_jobs
         SET status = 'running', updated_at = NOW()
         WHERE id = $1`,
        [job.id]
      );
      await client.query('COMMIT');
      return job;
    } catch (err) {
      await client.query('ROLLBACK');
      throw err;
    } finally {
      client.release();
    }
  }

  async updateProgress(
    jobId: string,
    status: SwarmJobRow['status'],
    progress: Record<string, unknown>,
    errorMessage?: string
  ): Promise<void> {
    await this.pool.query(
      `UPDATE swarm_jobs
       SET status = $2,
           progress = $3::jsonb,
           error_message = COALESCE($4, error_message),
           updated_at = NOW()
       WHERE id = $1`,
      [jobId, status, JSON.stringify(progress), errorMessage ?? null]
    );
  }
}
