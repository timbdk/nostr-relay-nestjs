import { BeforeApplicationShutdown, Injectable } from '@nestjs/common';
import { ConfigService } from '@nestjs/config';
import { Kysely, PostgresDialect, sql } from 'kysely';
import * as pg from 'pg';
import { Config } from 'src/config';
import { Database } from './types';

import { InjectPinoLogger, PinoLogger } from 'nestjs-pino';

@Injectable()
export class KyselyDb implements BeforeApplicationShutdown {
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
