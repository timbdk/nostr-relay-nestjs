import { BeforeApplicationShutdown, Injectable, OnModuleInit } from '@nestjs/common';
import { ConfigService } from '@nestjs/config';
import { Kysely, PostgresDialect, sql } from 'kysely';
import * as pg from 'pg';
import { Config } from 'src/config';
import { Database } from './types';

import { InjectPinoLogger, PinoLogger } from 'nestjs-pino';

@Injectable()
export class KyselyDb implements BeforeApplicationShutdown, OnModuleInit {
  private readonly db: Kysely<Database>;
  private readonly pool: pg.Pool;

  constructor(
    config: ConfigService<Config, true>,
    @InjectPinoLogger(KyselyDb.name)
    private readonly logger: PinoLogger,
  ) {
    const databaseConfig = config.get('database', { infer: true });

    const int8TypeId = 20;
    pg.types.setTypeParser(int8TypeId, (val) => parseInt(val, 10));

    this.pool = new pg.Pool({
      connectionString: databaseConfig.url,
      max: databaseConfig.maxConnections,
    });

    this.pool.on('error', (err) => {
      this.logger.warn('PostgreSQL pool: idle client error (connection will be replaced) — %s', err.message);
    });

    const dialect = new PostgresDialect({ pool: this.pool });
    this.db = new Kysely<any>({ dialect });
  }

  async onModuleInit() {
    let attempts = 0;
    const maxAttempts = 10;
    let delay = 1000;

    while (attempts < maxAttempts) {
      try {
        await sql`SELECT 1`.execute(this.db);
        this.logger.info('Successfully connected to the database.');
        return;
      } catch (err: any) {
        attempts++;
        this.logger.warn(
          { err },
          `Database connection failed (attempt ${attempts}/${maxAttempts}). Retrying in ${delay}ms...`,
        );
        if (attempts >= maxAttempts) {
          this.logger.fatal('Database unreachable after maximum retry attempts. Exiting.');
          process.exit(1);
        }
        await new Promise((resolve) => setTimeout(resolve, delay));
        delay = Math.min(delay * 1.5, 30000); // Exponential backoff up to 30s
      }
    }
  }

  async isHealthy(): Promise<boolean | string> {
    try {
      await sql`SELECT 1`.execute(this.db);
      return true;
    } catch (err: any) {
      this.logger.error({ err }, 'Health check database query failed');
      return err.message || String(err);
    }
  }

  getDb() {
    return this.db;
  }

  async beforeApplicationShutdown() {
    await this.db.destroy();
  }
}
