import { Kysely, sql } from 'kysely'

export async function up(db: Kysely<any>): Promise<void> {
  await sql`ALTER TABLE "events" ALTER COLUMN "sig" TYPE text`.execute(db)
}

// Reverting text to character(128) will throw "value too long" if any ML-DSA signatures
// (>128 chars) exist in the table. This is intentional and consistent with the set's
// wipe-boundary doctrine (databases are cleanly reset/wiped across major cryptographic sets).
export async function down(db: Kysely<any>): Promise<void> {
  await sql`ALTER TABLE "events" ALTER COLUMN "sig" TYPE character(128)`.execute(db)
}
