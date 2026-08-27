/**
 * Purpose: Cryptographic verification of Verity events according to the PQE Set A uniform path.
 * Behavior: Validates 8-slot canonical serialization, self-certifying keys, chain-verified keys via
 *           chain cache lookups, validity windows, delegation scopes, revocations, rotate countersignatures,
 *           and platform endorsements.
 * Usage: Consumed by NostrRelayService (asynchronous write gate) and EventUtils.validate (synchronous monkey-patch).
 */

// ── Imports ──────────────────────────────────────────────────────────────────

import { schnorr } from '@noble/curves/secp256k1.js'
import { sha256 } from '@noble/hashes/sha2.js'
import { bytesToHex, hexToBytes } from '@noble/hashes/utils.js'
import { base64 } from '@scure/base'
import { createHash } from 'crypto'

// ── Preimage Builders ────────────────────────────────────────────────────────

function canonicalChainContent(content: any): string {
  const parsed = typeof content === 'string' ? JSON.parse(content) : content
  return stringifyCanonical(parsed, true)
}

function stringifyCanonical(val: any, isRoot = false): string {
  if (val === null || typeof val !== 'object') {
    return JSON.stringify(val)
  }
  if (Array.isArray(val)) {
    return '[' + val.map((item) => (item === undefined ? 'null' : stringifyCanonical(item, false))).join(',') + ']'
  }
  const keys = Object.keys(val)
    .filter((k) => (isRoot ? k !== 'platform' : true) && val[k] !== undefined)
    .sort()
  return '{' + keys.map((k) => JSON.stringify(k) + ':' + stringifyCanonical(val[k], false)).join(',') + '}'
}

export function countersignPreimage(
  identityIdHex: string,
  newSignKeyHashHex: string | null | undefined,
  validFrom: number | string
): string | null {
  if (!newSignKeyHashHex) return null
  return `verity:keychain:297:${identityIdHex}:${newSignKeyHashHex}:${validFrom}`
}

export function endorsementPreimage(identityIdHex: string, variant: string, content: any): string {
  const canonicalStr = canonicalChainContent(content)
  const contentHash = bytesToHex(sha256(new TextEncoder().encode(canonicalStr)))
  return `verity:keychain:297:endorsement:${identityIdHex}:${variant}:${contentHash}`
}

// ── Types ────────────────────────────────────────────────────────────────────


export interface ChainLookupContext {
  platformId?: string
}

export type ChainLookupFn = (kid: string) => Promise<any> | any

// ── Helper Functions ─────────────────────────────────────────────────────────

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

function decodeSignature(sigStr: string): Uint8Array | null {
  if (typeof sigStr !== 'string' || !sigStr) return null
  try {
    if (sigStr.length === 128 && /^[0-9a-fA-F]+$/.test(sigStr)) {
      return hexToBytes(sigStr)
    }
    return base64.decode(sigStr)
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

// ── Verification Entry Points ────────────────────────────────────────────────

export async function verifyVerityEventAsync(
  event: any,
  serializationPrefix: number,
  chainLookup?: ChainLookupFn,
  context?: ChainLookupContext
): Promise<string | undefined> {
  return verifyVerityEventInternal(event, serializationPrefix, chainLookup, true, context)
}

export function verifyVerityEventSync(
  event: any,
  serializationPrefix: number,
  chainLookup?: ChainLookupFn,
  context?: ChainLookupContext
): string | undefined {
  return verifyVerityEventInternal(event, serializationPrefix, chainLookup, false, context) as string | undefined
}

// ── Main Verification Logic ──────────────────────────────────────────────────

const TRANSPORT_KINDS = new Set([22242, 24133, 24134, 24135])

function verifyVerityEventInternal(
  event: any,
  serializationPrefix: number,
  chainLookup?: ChainLookupFn,
  isAsync = false,
  context?: ChainLookupContext
): Promise<string | undefined> | (string | undefined) {
  // 1. Basic field format checks
  if (!event || typeof event !== 'object') {
    return 'invalid: event must be an object'
  }

  if (!event.id || typeof event.id !== 'string' || !/^[0-9a-f]{64}$/i.test(event.id)) {
    return 'invalid: id is wrong'
  }

  const uid = event.uid ?? event.pubkey
  if (!uid || typeof uid !== 'string' || !/^[0-9a-f]{64}$/i.test(uid)) {
    return event.uid ? 'invalid: uid is wrong' : 'invalid: pubkey is wrong'
  }

  if (!event.sig || typeof event.sig !== 'string' || !/^[0-9a-f]+$/i.test(event.sig)) {
    return 'invalid: signature is wrong'
  }

  if (typeof event.kind !== 'number') {
    return 'invalid: kind must be a number'
  }
  if (typeof event.created_at !== 'number') {
    return 'invalid: created_at must be a number'
  }
  if (!Array.isArray(event.tags)) {
    return 'invalid: tags must be an array'
  }
  if (typeof event.content !== 'string') {
    return 'invalid: content must be a string'
  }

  const hasKid = event.kid !== undefined && event.kid !== null && event.kid !== ''
  const hasKey = event.key !== undefined && event.key !== null && event.key !== ''

  // 2. Structural constraint: at most one of kid, key
  if (hasKid && hasKey) {
    return 'invalid: ambiguous — both kid and key present'
  }

  // 3. Kind-shape rules
  if (TRANSPORT_KINDS.has(event.kind)) {
    if (hasKid) return 'invalid: transport kind must not carry kid'
    if (!hasKey) return 'invalid: transport kind requires key field'
  }

  const isGenesis =
    event.kind === 297 &&
    (event.variant === 'genesis' ||
      (Array.isArray(event.tags) && event.tags.some((t: string[]) => t[0] === 'v' && t[1] === 'genesis')))

  if (event.kind === 297) {
    if (isGenesis) {
      if (hasKid || hasKey) {
        return 'invalid: Kind 297 genesis must not carry kid or key'
      }
    } else {
      if (hasKey) {
        return 'invalid: Kind 297 non-genesis must not carry key field'
      }
      if (!hasKid) {
        return 'invalid: Kind 297 non-genesis requires kid'
      }
    }
  } else if (!TRANSPORT_KINDS.has(event.kind) && event.kind !== 415) {
    if (hasKey) {
      return 'invalid: content events must not carry key'
    }
    if (!hasKid) {
      return 'invalid: content events must specify kid'
    }
  }

  // 4. ID recompute: 8-slot canonical serialization
  try {
    const serialized = JSON.stringify([
      serializationPrefix,
      uid,
      event.created_at,
      event.kind,
      event.tags,
      event.content,
      event.kid ?? '',
      event.key ?? '',
    ])
    const hash = createHash('sha256').update(serialized).digest()
    const computedId = hash.toString('hex')

    if (event.id !== computedId) {
      return 'invalid: id mismatch'
    }
  } catch (e: any) {
    return `invalid: id calculation failed: ${e.message}`
  }

  const idBytes = new Uint8Array(Buffer.from(event.id, 'hex'))
  const sigBytes = decodeSignature(event.sig)
  if (!sigBytes) {
    return 'invalid: signature is wrong'
  }

  // 5. Dispatch: Self-certifying branch (key present)
  if (hasKey) {
    const parsed = parsePublicKey(event.key)
    if (!parsed) {
      return 'invalid: malformed key field format'
    }
    if (parsed.alg !== 'secp256k1-schnorr') {
      return `invalid: unknown algorithm in key field: ${parsed.alg}`
    }

    const computedUid = bytesToHex(sha256(parsed.bytes))
    if (computedUid !== uid) {
      return 'invalid: uid does not match carried key'
    }

    if (!schnorr.verify(sigBytes, idBytes, parsed.bytes)) {
      return 'invalid: signature is wrong'
    }
    return undefined
  }

  // 6. Dispatch: Kind 297 genesis exemption (no kid, no key)
  if (isGenesis) {
    const content = extractContent(event)
    if (!content) return 'invalid: malformed content'

    const signKeyStr = content?.keys?.sign
    if (!signKeyStr || typeof signKeyStr !== 'string') {
      return 'invalid: Kind 297 genesis missing keys.sign'
    }
    const parsed = parsePublicKey(signKeyStr)
    if (!parsed) {
      return 'invalid: malformed sign key string in genesis'
    }
    if (parsed.alg !== 'secp256k1-schnorr') {
      return `invalid: unknown signing algorithm: ${parsed.alg}`
    }

    const expectedUid = bytesToHex(sha256(parsed.bytes))
    if (uid !== expectedUid) {
      return 'invalid: Kind 297 genesis uid does not match content.keys.sign'
    }

    if (!schnorr.verify(sigBytes, idBytes, parsed.bytes)) {
      return 'invalid: signature is wrong'
    }

    // Platform genesis exemption vs user genesis endorsement check
    const platformId = context?.platformId
    const isPlatformGenesis = Boolean(platformId && uid === platformId)

    if (isPlatformGenesis) {
      if (content.platform) {
        return 'invalid: platform genesis must not carry platform endorsement'
      }
      return undefined
    }

    // User genesis requires platform endorsement
    if (chainLookup) {
      if (isAsync) {
        return (async () => {
          const endorsingEntry = await chainLookup(content.platform?.entry)
          return checkEndorsement(endorsingEntry, uid, 'genesis', content, platformId)
        })()
      } else {
        const endorsingEntry = chainLookup(content.platform?.entry)
        return checkEndorsement(endorsingEntry, uid, 'genesis', content, platformId)
      }
    }

    return undefined
  }

  // 7. Dispatch: Chain-verified branch (kid present)
  if (hasKid) {
    if (!chainLookup) {
      if (!isAsync) return undefined
      return 'invalid: chain lookup required for kid verification'
    }

    if (isAsync) {
      return (async () => {
        try {
          const entry = await chainLookup(event.kid)
          return await verifyChainEntryHelper(entry, event, uid, sigBytes, idBytes, chainLookup, context?.platformId, true)
        } catch (e: any) {
          return `invalid: chain verification failed: ${e.message}`
        }
      })()
    } else {
      try {
        const entry = chainLookup(event.kid)
        return verifyChainEntryHelper(entry, event, uid, sigBytes, idBytes, chainLookup, context?.platformId, false)
      } catch (e: any) {
        return `invalid: chain verification failed: ${e.message}`
      }
    }
  }

  // 8. Neither kid nor key present
  return 'invalid: missing kid or key'
}

// ── Chain Entry Helpers ──────────────────────────────────────────────────────

function verifyChainEntryHelper(
  entry: any,
  event: any,
  uid: string,
  sigBytes: Uint8Array,
  idBytes: Uint8Array,
  chainLookup: ChainLookupFn,
  platformId?: string,
  isAsync = false
): Promise<string | undefined> | (string | undefined) {
  if (!entry) {
    return `invalid: [CHAIN_ENTRY_UNKNOWN]: referenced chain entry ${event.kid} not found`
  }
  if (entry.kind !== 297) {
    return 'invalid: referenced chain entry is not Kind 297'
  }

  const entryUid = entry.uid ?? entry.pubkey
  if (entryUid !== uid) {
    return 'invalid: event uid does not match chain entry uid'
  }

  // Acceptance rule: reject seen-revoked entries
  if (entry.revokedBy) {
    return 'invalid: referenced chain entry has been revoked'
  }

  const entryContent = extractContent(entry)
  if (!entryContent) {
    return 'invalid: referenced chain entry has malformed content'
  }

  // Delegate scope check
  const isDelegate =
    entry.variant === 'delegate' ||
    (Array.isArray(entry.tags) && entry.tags.some((t: string[]) => t[0] === 'v' && t[1] === 'delegate'))
  if (isDelegate) {
    if (event.kind === 297 || event.kind === 415) {
      return `invalid: delegate scope does not allow kind ${event.kind}`
    }
    if (entryContent.scope?.kinds && Array.isArray(entryContent.scope.kinds)) {
      if (!entryContent.scope.kinds.includes(event.kind)) {
        return `invalid: delegate scope does not allow kind ${event.kind}`
      }
    }
  }

  // Validity window check
  if (entryContent.valid?.from && event.created_at < entryContent.valid.from) {
    return 'invalid: entry not yet valid'
  }
  if (entryContent.valid?.until && event.created_at > entryContent.valid.until) {
    return 'invalid: delegate key expired'
  }

  const signKeyStr = entryContent?.keys?.sign
  if (!signKeyStr || typeof signKeyStr !== 'string') {
    return 'invalid: referenced chain entry missing keys.sign'
  }
  const parsed = parsePublicKey(signKeyStr)
  if (!parsed) {
    return 'invalid: malformed sign key in referenced chain entry'
  }
  if (parsed.alg !== 'secp256k1-schnorr') {
    return `invalid: unknown signing algorithm: ${parsed.alg}`
  }

  if (!schnorr.verify(sigBytes, idBytes, parsed.bytes)) {
    return 'invalid: signature is wrong'
  }

  // Kind 297 internal write-time proofs
  if (event.kind === 297) {
    const variant = extractVariant(event)
    const content = extractContent(event)

    // 1. Rotate countersignature
    if (variant === 'rotate' && content?.keys?.sign) {
      if (!content.countersign) {
        return 'invalid: rotate with keys.sign missing countersign'
      }
      const newSignKey = parsePublicKey(content.keys.sign)
      if (!newSignKey || newSignKey.alg !== 'secp256k1-schnorr') {
        return 'invalid: malformed new sign key in rotate'
      }
      const newSignKeyHash = bytesToHex(sha256(newSignKey.bytes))
      const preimage = countersignPreimage(uid, newSignKeyHash, content.valid.from)
      if (!preimage) {
        return 'invalid: failed to construct countersign preimage'
      }
      const preimageHash = sha256(new TextEncoder().encode(preimage))
      const counterSigBytes = decodeSignature(content.countersign)
      if (!counterSigBytes || !schnorr.verify(counterSigBytes, preimageHash, newSignKey.bytes)) {
        return 'invalid: invalid countersignature'
      }
    }

    // 2. Platform Endorsement verification
    if (variant && variant !== 'genesis') {
      if (isAsync) {
        return (async () => {
          const endorsingEntry = await chainLookup(content.platform?.entry)
          return checkEndorsement(endorsingEntry, uid, variant, content, platformId)
        })()
      } else {
        const endorsingEntry = chainLookup(content.platform?.entry)
        return checkEndorsement(endorsingEntry, uid, variant, content, platformId)
      }
    }
  }

  return undefined
}

function checkEndorsement(
  endorsingEntry: any,
  uid: string,
  variant: string,
  content: any,
  platformId?: string
): string | undefined {
  if (!content?.platform) {
    return 'invalid: missing platform endorsement'
  }
  if (!content.platform.entry || !content.platform.b64) {
    return 'invalid: malformed platform endorsement'
  }
  if (!endorsingEntry) {
    return `invalid: endorsing entry ${content.platform.entry} not found`
  }

  const endorsingUid = endorsingEntry.uid ?? endorsingEntry.pubkey
  if (platformId && endorsingUid !== platformId) {
    return 'invalid: endorsing entry does not belong to platform identity'
  }

  const endorsingContent = extractContent(endorsingEntry)
  if (!endorsingContent?.keys?.sign) {
    return 'invalid: endorsing entry missing keys.sign'
  }

  const endorsingKey = parsePublicKey(endorsingContent.keys.sign)
  if (!endorsingKey || endorsingKey.alg !== 'secp256k1-schnorr') {
    return 'invalid: malformed endorsing key'
  }

  const endorsementStr = endorsementPreimage(uid, variant, content)
  const endorsementHash = sha256(new TextEncoder().encode(endorsementStr))
  const endorsementSigBytes = decodeSignature(content.platform.b64)
  if (!endorsementSigBytes) {
    return 'invalid: malformed platform endorsement signature'
  }

  if (!schnorr.verify(endorsementSigBytes, endorsementHash, endorsingKey.bytes)) {
    return 'invalid: invalid platform endorsement signature'
  }

  return undefined
}

