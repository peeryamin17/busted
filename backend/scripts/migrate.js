// Applies pending SQL migrations from ../migrations in filename order.
//
// Safe to re-run: applied files are recorded in the schema_migrations table
// and skipped, so this can be run after every deploy without harm. Each file
// is applied in its own transaction — a failed file rolls back and stops the
// run instead of leaving a half-applied schema behind.
//
// Usage (from the backend directory):
//   DATABASE_URL=<postgres connection string> npm run migrate
//
// Plain Node on purpose: it must work in a production install where
// devDependencies (tsx, typescript) may be absent. Loads ./.env for local
// runs via dotenv (a runtime dependency); on Render the variables come from
// the service environment directly.
require('dotenv/config');
const fs = require('node:fs');
const path = require('node:path');
const { Pool } = require('pg');

async function main() {
  const connectionString = process.env.DATABASE_URL;
  if (!connectionString) {
    console.error('[migrate] DATABASE_URL is not set — nothing to migrate against.');
    process.exit(1);
  }

  const migrationsDir = path.join(__dirname, '..', 'migrations');
  const files = fs
    .readdirSync(migrationsDir)
    .filter((f) => f.endsWith('.sql'))
    .sort();
  if (files.length === 0) {
    console.log('[migrate] no .sql files found — nothing to do.');
    return;
  }

  const pool = new Pool({ connectionString });
  try {
    await pool.query(`CREATE TABLE IF NOT EXISTS schema_migrations (
      name text PRIMARY KEY,
      applied_at timestamptz NOT NULL DEFAULT now()
    )`);
    const { rows } = await pool.query('SELECT name FROM schema_migrations');
    const applied = new Set(rows.map((r) => r.name));

    let count = 0;
    for (const file of files) {
      if (applied.has(file)) {
        console.log(`[migrate] skip ${file} (already applied)`);
        continue;
      }
      const sql = fs.readFileSync(path.join(migrationsDir, file), 'utf8');
      const client = await pool.connect();
      try {
        await client.query('BEGIN');
        await client.query(sql);
        await client.query('INSERT INTO schema_migrations (name) VALUES ($1)', [file]);
        await client.query('COMMIT');
        console.log(`[migrate] applied ${file}`);
        count += 1;
      } catch (err) {
        await client.query('ROLLBACK');
        throw new Error(`${file}: ${err.message}`);
      } finally {
        client.release();
      }
    }
    console.log(`[migrate] done (${count} applied, ${files.length - count} already present)`);
  } finally {
    await pool.end();
  }
}

main().catch((err) => {
  console.error('[migrate] failed:', err.message);
  process.exit(1);
});
