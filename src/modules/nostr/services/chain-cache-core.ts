/**
 * Purpose: Decorator-free chain cache core for Kind 297 Key Chains.
 * Behavior: Backfills chain entries from storage on startup with readiness gate;
 *           applies accepted Kind 297 events synchronously on the write path before OK ack;
 *           provides multi-entry indexing, hold-until-first-use tracking, eviction sweep,
 *           and platform service recognition.
 * Usage: Wrapped by ChainCacheService (NestJS shell) for DI registration and cron scheduling.
 *        Imported directly by unit tests without NestJS dependencies.
 */

// ── Imports ──────────────────────────────────────────────────────────────────

import { sha256 } from '@noble/hashes/sha2.js'
import { bytesToHex, hexToBytes } from '@noble/hashes/utils.js'
import { base64 } from '@scure/base'

// ── Types ────────────────────────────────────────────────────────────────────

export interface ChainEntry {
  id: string
  uid: string
  created_at: number
  kind: number
  variant: 'genesis' | 'rotate' | 'delegate' | 'revoke'
  kid?: string
  content: any
  signKeyHash?: string
  signKeyAlg?: string
  signKeyBytes?: Uint8Array
  revokedBy?: string
  revokedEntryId?: string
}

/** Minimal logger interface — satisfied by pino, console, or test mocks. */
export interface ChainCacheLogger {
  info(msg: string): void
  warn(msg: string): void
  error(msg: string): void
  debug(msg: string): void
}

/** Minimal repository interface — satisfied by EventRepository or test mocks. */
export interface ChainCacheEventRepository {
  setHeldChecker(checker: (id: string) => boolean): void
  onInsert(listener: (event: any) => void): () => void
  find(filter: any): Promise<any[]>
}

/** Minimal checkpoint broadcaster — satisfied by TestingCheckpointService or test mocks. */
export interface ChainCacheCheckpointService {
  broadcast(name: string, data: any): void
}

/** Constructor options for the core cache. */
export interface ChainCacheCoreOptions {
  logger: ChainCacheLogger
  eventRepository: ChainCacheEventRepository
  platformId: string
  createdAtLowerLimit?: number
  checkpointService?: ChainCacheCheckpointService
}

// ── Pure Helpers ─────────────────────────────────────────────────────────────

function parsePublicKey(keyStr: string): { alg: string; bytes: Uint8Array } | null {
  if (typeof keyStr !== 'string' || !keyStr) return null
  try {
    if (keyStr.includes(':')) {
      const colonIdx = keyStr.indexOf(':')
      const alg = keyStr.substring(0, colonIdx)
      const bytes = base64.decode(keyStr.substring(colonIdx + 1))
      return { alg, bytes }
    }
    if (/^[a-f0-9]{64}$/i.test(keyStr)) {
      return { alg: 'secp256k1-schnorr', bytes: hexToBytes(keyStr) }
    }
    return { alg: 'secp256k1-schnorr', bytes: base64.decode(keyStr) }
  } catch {
    return null
  }
}

function extractVariant(event: any): 'genesis' | 'rotate' | 'delegate' | 'revoke' | null {
  if (event.variant) return event.variant
  const vTag = event.tags?.find((t: string[]) => t[0] === 'v')
  return vTag?.[1] ?? null
}

function extractContent(event: any): any {
  if (typeof event.content === 'string') {
    try {
      return JSON.parse(event.content)
    } catch {
      return null
    }
  }
  return event.content
}

// ── Core Cache ───────────────────────────────────────────────────────────────

export class ChainCacheCore {
  private readonly platformId: string
  private readonly createdAtLowerLimit: number
  private chainReady = false

  // Indexes
  private readonly entriesByUid = new Map<string, ChainEntry[]>()
  private readonly entryById = new Map<string, ChainEntry>()
  private readonly entryByCertifiedKeyHash = new Map<string, ChainEntry>()
  private readonly heldEntryIds = new Set<string>()

  private readonly logger: ChainCacheLogger
  private readonly eventRepository: ChainCacheEventRepository
  private readonly checkpointService?: ChainCacheCheckpointService

  constructor(options: ChainCacheCoreOptions) {
    this.logger = options.logger
    this.eventRepository = options.eventRepository
    this.checkpointService = options.checkpointService
    this.platformId = options.platformId
    this.createdAtLowerLimit = options.createdAtLowerLimit ?? 86400
  }

  init() {
    // Register held entry egress filter
    this.eventRepository.setHeldChecker((id) => this.heldEntryIds.has(id))

    // Subscribe synchronously to repository post-insert notifications
    this.eventRepository.onInsert((event) => {
      if (event.kind === 297) {
        this.applyEvent(event)
      }
    })
  }

  // ── Backfill & Readiness Gate ──────────────────────────────────────────────

  async backfill(): Promise<void> {
    const backfillTimeoutMs = parseInt(process.env.CHAIN_BACKFILL_TIMEOUT_MS || '30000', 10)
    const timeoutHandle = setTimeout(() => {
      this.logger.error(`[CHAIN_CACHE] Cold-start backfill exceeded timeout of ${backfillTimeoutMs}ms! Fatal exit.`)
      process.exit(1)
    }, backfillTimeoutMs)

    try {
      this.logger.info('[CHAIN_CACHE] Starting cold-start backfill from storage...')
      const events = await this.eventRepository.find({ kinds: [297], limit: 100000 })

      // Sort by created_at ascending so predecessors and revokes are applied in order
      events.sort((a, b) => a.created_at - b.created_at)

      for (const event of events) {
        this.applyEvent(event, true)
      }

      this.chainReady = true
      clearTimeout(timeoutHandle)

      const totalEntries = this.entryById.size
      this.logger.info(`[CHAIN_CACHE] Backfill completed. Loaded ${totalEntries} chain entries for ${this.entriesByUid.size} identities.`)

      this.checkpointService?.broadcast('relay.chain.backfilled', {
        count: totalEntries,
      })
    } catch (error) {
      clearTimeout(timeoutHandle)
      this.logger.error(`[CHAIN_CACHE] Backfill failed: ${(error as Error).message}`)
      throw error
    }
  }

  isReady(): boolean {
    return this.chainReady
  }

  // ── Write-Path Application ─────────────────────────────────────────────────

  /**
   * Applies an accepted Kind 297 event into the in-memory cache.
   * @param isBackfill If true, backfill mode (avoids re-broadcasting apply checkpoints).
   */
  applyEvent(event: any, isBackfill = false): void {
    if (this.entryById.has(event.id)) {
      return // Duplicate event, already in cache
    }

    const variant = extractVariant(event)
    if (!variant) return

    const content = extractContent(event)
    if (!content) return

    const uid = event.uid ?? event.pubkey
    let signKeyHash: string | undefined
    let signKeyAlg: string | undefined
    let signKeyBytes: Uint8Array | undefined

    if (content.keys?.sign) {
      const parsedKey = parsePublicKey(content.keys.sign)
      if (parsedKey) {
        signKeyAlg = parsedKey.alg
        signKeyBytes = parsedKey.bytes
        signKeyHash = bytesToHex(sha256(parsedKey.bytes))
      }
    }

    const entry: ChainEntry = {
      id: event.id,
      uid,
      created_at: Number(event.created_at),
      kind: 297,
      variant,
      kid: event.kid ?? undefined,
      content,
      signKeyHash,
      signKeyAlg,
      signKeyBytes,
    }

    // 1. Primary UID index
    const userEntries = this.entriesByUid.get(uid) || []
    userEntries.push(entry)
    this.entriesByUid.set(uid, userEntries)

    // 2. Entry ID index
    this.entryById.set(entry.id, entry)
    this.logger.debug(
      `[CHAIN_CACHE] applyEvent added: id=${entry.id} variant=${variant} uid=${uid.substring(0, 16)} signKeyHash=${signKeyHash?.substring(0, 16)} (isBackfill=${isBackfill})`
    )

    // 3. Certified Key Hash index
    if (signKeyHash) {
      this.entryByCertifiedKeyHash.set(signKeyHash, entry)
    }

    // 4. Revocation linking
    if (variant === 'revoke') {
      const eTag = Array.isArray(event.tags) ? event.tags.find((t: string[]) => t[0] === 'e') : null
      const revokedTargetId = eTag?.[1] || content.revoked?.entry
      if (revokedTargetId) {
        entry.revokedEntryId = revokedTargetId
        const targetEntry = this.entryById.get(revokedTargetId)
        if (targetEntry) {
          targetEntry.revokedBy = entry.id
        }
      }
    }

    // 5. Hold-until-first-use: user-chain delegate entries only
    // Platform-chain entries and non-delegate entries are never held
    if (variant === 'delegate' && uid !== this.platformId) {
      this.heldEntryIds.add(entry.id)
    }

    if (!isBackfill) {
      this.checkpointService?.broadcast('relay.chain.entry_applied', {
        entryId: entry.id,
        variant: entry.variant,
      })
    }
  }

  // ── Hold-until-first-use & Egress Filtering ────────────────────────────────

  isHeld(entryId: string): boolean {
    return this.heldEntryIds.has(entryId)
  }

  release(entryId: string): void {
    if (this.heldEntryIds.has(entryId)) {
      this.heldEntryIds.delete(entryId)
      this.checkpointService?.broadcast('relay.chain.entry_released', {
        entryId,
      })
    }
  }

  // ── Eviction Sweep ─────────────────────────────────────────────────────────

  evictionSweep(): void {
    const now = Math.floor(Date.now() / 1000)
    const expiryThreshold = now - this.createdAtLowerLimit

    for (const [entryId, entry] of this.entryById.entries()) {
      // Only delegate entries carry valid.until in practice
      if (entry.variant === 'delegate' && entry.content?.valid?.until) {
        if (entry.content.valid.until < expiryThreshold) {
          this.evictEntry(entryId)
        }
      }
    }
  }

  private evictEntry(entryId: string): void {
    const entry = this.entryById.get(entryId)
    if (!entry) return

    this.entryById.delete(entryId)
    this.heldEntryIds.delete(entryId)

    if (entry.signKeyHash) {
      this.entryByCertifiedKeyHash.delete(entry.signKeyHash)
    }

    const userEntries = this.entriesByUid.get(entry.uid)
    if (userEntries) {
      const filtered = userEntries.filter((e) => e.id !== entryId)
      if (filtered.length === 0) {
        this.entriesByUid.delete(entry.uid)
      } else {
        this.entriesByUid.set(entry.uid, filtered)
      }
    }
  }

  // ── Query & Membership Helpers ─────────────────────────────────────────────

  byId(entryId: string): ChainEntry | null {
    const entry = this.entryById.get(entryId) ?? null
    if (!entry) {
      this.logger.debug(`[CHAIN_CACHE] byId lookup miss for entryId=${entryId}`)
    }
    return entry
  }

  byUid(uid: string): ChainEntry[] {
    return this.entriesByUid.get(uid) ?? []
  }

  isUserRegistered(uid: string): boolean {
    const entries = this.entriesByUid.get(uid)
    return Boolean(entries && entries.length > 0)
  }

  isTrustedService(uid: string): boolean {
    if (!uid) return false
    const entry = this.entryByCertifiedKeyHash.get(uid)
    if (!entry) return false
    return entry.uid === this.platformId && entry.variant === 'delegate'
  }

  getTrustedServiceUids(): string[] {
    const trustedUids: string[] = []
    for (const [keyHash, entry] of this.entryByCertifiedKeyHash.entries()) {
      if (entry.uid === this.platformId && entry.variant === 'delegate') {
        trustedUids.push(keyHash)
      }
    }
    return trustedUids
  }

  // ── Testing Reset ──────────────────────────────────────────────────────────

  setChainReady(ready: boolean): void {
    this.chainReady = ready
    if (ready) {
      this.checkpointService?.broadcast('relay.chain.backfilled', {
        count: this.entryById.size,
      })
    }
  }

  async reset(): Promise<void> {
    this.entriesByUid.clear()
    this.entryById.clear()
    this.entryByCertifiedKeyHash.clear()
    this.heldEntryIds.clear()
    this.chainReady = false
    await this.backfill()
  }
}
