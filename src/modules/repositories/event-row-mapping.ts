/**
 * Purpose: Pure, dependency-free mapping functions between Nostr events and Postgres database rows.
 * Behavior: Extracts generic tag indexes and builds row values for `events` and `generic_tags` tables.
 * Usage: Consumed by Relay event repository, Test Runner platform seed tooling, and Dev Seed container.
 */

// ── Tag Extraction Helpers ───────────────────────────────────────────────────

export function isGenericTagName(tagName: string): boolean {
  return /^[a-zA-Z]$/.test(tagName)
}

export function toGenericTag(tagName: string, tagValue: string): string {
  return `${tagName}:${tagValue}`
}

export function extractExpirationTimestamp(event: { tags?: string[][] }): number | null {
  if (!event.tags || !Array.isArray(event.tags)) return null
  const expTag = event.tags.find((t) => t[0] === 'expiration')
  if (!expTag || !expTag[1]) return null
  const num = parseInt(expTag[1], 10)
  return isNaN(num) ? null : num
}

export function extractDTagValue(event: { tags?: string[][] }): string | null {
  if (!event.tags || !Array.isArray(event.tags)) return null
  const dTag = event.tags.find((t) => t[0] === 'd')
  if (!dTag) return null
  return dTag[1] ?? ''
}

export function extractGenericTagsFrom(event: { tags?: string[][] }): string[] {
  if (!event.tags || !Array.isArray(event.tags)) return []
  const genericTagSet = new Set<string>()
  event.tags.forEach(([tagName, tagValue]) => {
    if (tagName && tagValue !== undefined && isGenericTagName(tagName)) {
      genericTagSet.add(toGenericTag(tagName, tagValue))
    }
  })
  return [...genericTagSet]
}

// ── Database Row Builders ────────────────────────────────────────────────────

export interface EventRowData {
  id: string
  uid: string
  kind: number
  created_at: number
  tags: string
  generic_tags: string[]
  content: string
  sig: string
  expired_at: number | null
  d_tag_value: string | null
  kid: string | null
  key: string | null
}

export interface GenericTagRowData {
  tag: string
  event_id: string
  kind: number
  uid: string
  created_at: number
}

export function buildEventRow(event: any): EventRowData {
  const uid = event.uid ?? event.pubkey
  const kid = event.kid ?? null
  const key = event.key ?? null
  const expiredAt = extractExpirationTimestamp(event)
  const dTagValue = extractDTagValue(event)
  const genericTags = extractGenericTagsFrom(event)
  const tags = typeof event.tags === 'string' ? event.tags : JSON.stringify(event.tags ?? [])

  return {
    id: event.id,
    uid,
    kind: event.kind,
    created_at: event.created_at,
    tags,
    generic_tags: genericTags,
    content: event.content ?? '',
    sig: event.sig,
    expired_at: expiredAt,
    d_tag_value: dTagValue,
    kid,
    key
  }
}

export function buildGenericTagRows(event: any, genericTags?: string[]): GenericTagRowData[] {
  const tags = genericTags ?? extractGenericTagsFrom(event)
  const uid = event.uid ?? event.pubkey
  return tags.map((tag) => ({
    tag,
    event_id: event.id,
    kind: event.kind,
    uid,
    created_at: event.created_at
  }))
}
