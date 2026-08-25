import { Kysely } from 'kysely'

export async function up(db: Kysely<any>): Promise<void> {
  await db.schema.alterTable('events').addColumn('kid', 'text').addColumn('key', 'text').execute()
}

export async function down(db: Kysely<any>): Promise<void> {
  await db.schema.alterTable('events').dropColumn('kid').dropColumn('key').execute()
}
