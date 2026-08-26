import { Kysely, sql } from 'kysely'

export async function up(db: Kysely<any>): Promise<void> {
  // Drop author-based indexes on events
  await sql`DROP INDEX IF EXISTS "e_author_kind_d_tag_value_idx"`.execute(db)
  await sql`DROP INDEX IF EXISTS "e_author_created_at_idx"`.execute(db)
  await sql`DROP INDEX IF EXISTS "e_author_kind_created_at_idx"`.execute(db)

  // Drop author column on events
  await sql`ALTER TABLE "events" DROP COLUMN "author"`.execute(db)

  // Rename pubkey to uid on events
  await sql`ALTER TABLE "events" RENAME COLUMN "pubkey" TO "uid"`.execute(db)

  // Drop author-based index on generic_tags
  await sql`DROP INDEX IF EXISTS "g_author_tag_kind_created_at_desc_event_id_idx"`.execute(db)

  // Rename author to uid on generic_tags
  await sql`ALTER TABLE "generic_tags" RENAME COLUMN "author" TO "uid"`.execute(db)

  // Recreate indexes using uid
  await sql`CREATE UNIQUE INDEX "e_uid_kind_d_tag_value_idx" ON "events" ("uid", "kind", "d_tag_value") WHERE "d_tag_value" IS NOT NULL`.execute(db)
  await sql`CREATE INDEX "e_uid_created_at_idx" ON "events" ("uid", "created_at")`.execute(db)
  await sql`CREATE INDEX "e_uid_kind_created_at_idx" ON "events" ("uid", "kind", "created_at")`.execute(db)
  await sql`CREATE INDEX "g_uid_tag_kind_created_at_desc_event_id_idx" ON "generic_tags" ("uid", "tag", "kind", "created_at" DESC, "event_id")`.execute(db)
}

export async function down(db: Kysely<any>): Promise<void> {
  // Drop uid-based indexes
  await sql`DROP INDEX IF EXISTS "g_uid_tag_kind_created_at_desc_event_id_idx"`.execute(db)
  await sql`DROP INDEX IF EXISTS "e_uid_kind_created_at_idx"`.execute(db)
  await sql`DROP INDEX IF EXISTS "e_uid_created_at_idx"`.execute(db)
  await sql`DROP INDEX IF EXISTS "e_uid_kind_d_tag_value_idx"`.execute(db)

  // Rename uid back to author on generic_tags
  await sql`ALTER TABLE "generic_tags" RENAME COLUMN "uid" TO "author"`.execute(db)

  // Recreate author index on generic_tags
  await sql`CREATE INDEX "g_author_tag_kind_created_at_desc_event_id_idx" ON "generic_tags" ("author", "tag", "kind", "created_at" DESC, "event_id")`.execute(db)

  // Rename uid back to pubkey on events
  await sql`ALTER TABLE "events" RENAME COLUMN "uid" TO "pubkey"`.execute(db)

  // Add author column back to events and copy pubkey
  await sql`ALTER TABLE "events" ADD COLUMN "author" character(64)`.execute(db)
  await sql`UPDATE "events" SET "author" = "pubkey"`.execute(db)
  await sql`ALTER TABLE "events" ALTER COLUMN "author" SET NOT NULL`.execute(db)

  // Recreate author indexes on events
  await sql`CREATE UNIQUE INDEX "e_author_kind_d_tag_value_idx" ON "events" ("author", "kind", "d_tag_value") WHERE "d_tag_value" IS NOT NULL`.execute(db)
  await sql`CREATE INDEX "e_author_created_at_idx" ON "events" ("author", "created_at")`.execute(db)
  await sql`CREATE INDEX "e_author_kind_created_at_idx" ON "events" ("author", "kind", "created_at")`.execute(db)
}
