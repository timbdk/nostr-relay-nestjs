import 'dotenv/config';

import { promises as fs } from 'fs';
import {
  FileMigrationProvider,
  Kysely,
  Migrator,
  PostgresDialect,
  sql,
} from 'kysely';
import * as path from 'path';
import { Pool } from 'pg';
import { migrateMigrationsTable } from './migrate-old-migrations-table';

async function waitForDatabase(db: Kysely<any>) {
  let attempts = 0;
  const maxAttempts = 30;
  let delay = 500;

  while (attempts < maxAttempts) {
    try {
      await sql`SELECT 1`.execute(db);
      console.log('Database is ready.');
      return;
    } catch (err: any) {
      attempts++;
      console.warn(
        `Database not ready yet (attempt ${attempts}/${maxAttempts}). Retrying in ${delay}ms...`
      );
      if (attempts >= maxAttempts) {
        console.error('Database connection timed out.');
        throw err;
      }
      await new Promise((resolve) => setTimeout(resolve, delay));
      delay = Math.min(delay * 1.5, 2000);
    }
  }
}

async function migrateToLatest() {
  const db = new Kysely<any>({
    dialect: new PostgresDialect({
      pool: new Pool({
        connectionString: process.env.DATABASE_URL,
      }),
    }),
  });

  await waitForDatabase(db);

  await migrateMigrationsTable(db);

  const migrator = new Migrator({
    db,
    provider: new FileMigrationProvider({
      fs,
      path,
      // This needs to be an absolute path.
      migrationFolder: path.join(__dirname, '../migrations'),
    }),
    migrationTableName: 'kysely_migrations',
  });

  const { error, results } = await migrator.migrateToLatest();

  results?.forEach((it) => {
    if (it.status === 'Success') {
      console.log(`migration "${it.migrationName}" was executed successfully`);
    } else if (it.status === 'Error') {
      console.error(`failed to execute migration "${it.migrationName}"`);
    }
  });

  if (error) {
    console.error('failed to migrate');
    console.error(error);
    process.exit(1);
  }

  await db.destroy();
}

migrateToLatest();
