// eslint-disable-next-line @typescript-eslint/no-require-imports
const { schnorr } = require('@noble/curves/secp256k1.js')
import { createHash } from 'crypto'
import type { Event } from '@nostr-relay/common'

/**
 * Verity event verification using @noble/curves and Node.js crypto.
 *
 * Implements the uniform-path verification skeleton:
 * - 8-slot canonical serialization: [prefix, uid, created_at, kind, tags, content, kid, key]
 * - Self-certifying verification (key carried, uid == H(key))
 * - Chain-verified verification (kid carried, resolves via chainLookup)
 * - Kind 297 genesis self-certification exemption (content.keys.sign, uid == H(sign key))
 *
 * Returns a string on error, undefined on success — matching the EventUtils.validate contract.
 */

export async function verifyVerityEventAsync(
  event: any,
  serializationPrefix: number,
  chainLookup?: (kid: string) => Promise<any> | any
): Promise<string | undefined> {
  return verifyVerityEventInternal(event, serializationPrefix, chainLookup, true)
}

export function verifyVerityEventSync(
  event: any,
  serializationPrefix: number,
  chainLookup?: (kid: string) => any
): string | undefined {
  return verifyVerityEventInternal(event, serializationPrefix, chainLookup, false) as string | undefined
}

function verifyVerityEventInternal(
  event: any,
  serializationPrefix: number,
  chainLookup?: (kid: string) => Promise<any> | any,
  isAsync = false
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

  // 2. Structural constraint: at most one of kid, key
  const hasKid = event.kid !== undefined && event.kid !== null && event.kid !== ''
  const hasKey = event.key !== undefined && event.key !== null && event.key !== ''

  if (hasKid && hasKey) {
    return 'invalid: ambiguous — both kid and key present'
  }

  // 3. ID recompute: 8-slot canonical serialization
  try {
    const serialized = JSON.stringify([
      serializationPrefix,
      uid,
      event.created_at,
      event.kind,
      event.tags,
      event.content,
      event.kid ?? '',
      event.key ?? ''
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
  const sigBytes = new Uint8Array(Buffer.from(event.sig, 'hex'))

  // 4. Dispatch: Self-certifying branch (key present)
  if (hasKey) {
    const colonIdx = event.key.indexOf(':')
    if (colonIdx === -1) {
      return 'invalid: malformed key field format'
    }
    const alg = event.key.substring(0, colonIdx)
    if (alg !== 'secp256k1-schnorr') {
      return `invalid: unknown algorithm in key field: ${alg}`
    }
    try {
      const b64 = event.key.substring(colonIdx + 1)
      const keyBytes = Buffer.from(b64, 'base64')
      const computedUid = createHash('sha256').update(new Uint8Array(keyBytes)).digest('hex')
      if (computedUid !== uid) {
        return 'invalid: uid does not match carried key'
      }

      const pkBytes = new Uint8Array(keyBytes)
      if (!schnorr.verify(sigBytes, idBytes, pkBytes)) {
        return 'invalid: signature is wrong'
      }
      return undefined
    } catch {
      return 'invalid: signature verification failed'
    }
  }

  // 5. Dispatch: Kind 297 genesis exemption (no kid, no key)
  const isGenesis =
    event.kind === 297 &&
    (event.variant === 'genesis' ||
      (Array.isArray(event.tags) && event.tags.some((t: string[]) => t[0] === 'v' && t[1] === 'genesis')))

  if (isGenesis) {
    try {
      const content = typeof event.content === 'string' ? JSON.parse(event.content) : event.content
      const signKeyStr = content?.keys?.sign
      if (!signKeyStr || typeof signKeyStr !== 'string') {
        return 'invalid: Kind 297 genesis missing keys.sign'
      }
      const colonIdx = signKeyStr.indexOf(':')
      if (colonIdx === -1) {
        return 'invalid: malformed sign key string in genesis'
      }
      const alg = signKeyStr.substring(0, colonIdx)
      if (alg !== 'secp256k1-schnorr') {
        return `invalid: unknown signing algorithm: ${alg}`
      }
      const signKeyBytes = Buffer.from(signKeyStr.substring(colonIdx + 1), 'base64')
      const expectedUid = createHash('sha256').update(new Uint8Array(signKeyBytes)).digest('hex')
      if (uid !== expectedUid) {
        return 'invalid: Kind 297 genesis uid does not match content.keys.sign'
      }

      const pkBytes = new Uint8Array(signKeyBytes)
      if (!schnorr.verify(sigBytes, idBytes, pkBytes)) {
        return 'invalid: signature is wrong'
      }
      return undefined
    } catch {
      return 'invalid: failed to verify Kind 297 genesis'
    }
  }

  // 6. Dispatch: Chain-verified branch (kid present)
  if (hasKid) {
    if (!chainLookup) {
      // In synchronous pre-filter mode without chainLookup, structural validation and ID recompute passed.
      // Full cryptographic chain verification is deferred to the async write gate.
      if (!isAsync) return undefined
      return 'invalid: chain lookup required for kid verification'
    }

    // The async IIFE is intentional: verifyVerityEventInternal serves both sync and async callers.
    // Keeping the outer function non-async allows synchronous return values for verifyVerityEventSync
    // while awaiting the async chainLookup promise when isAsync is true.
    if (isAsync) {
      return (async () => {
        try {
          const entry = await chainLookup(event.kid)
          return verifyChainEntryHelper(entry, event, uid, sigBytes, idBytes)
        } catch (e: any) {
          return `invalid: chain verification failed: ${e.message}`
        }
      })()
    } else {
      try {
        const entry = chainLookup(event.kid)
        return verifyChainEntryHelper(entry, event, uid, sigBytes, idBytes)
      } catch (e: any) {
        return `invalid: chain verification failed: ${e.message}`
      }
    }
  }

  // 7. Neither kid nor key present
  return 'invalid: missing kid or key'
}

function verifyChainEntryHelper(
  entry: any,
  event: any,
  uid: string,
  sigBytes: Uint8Array,
  idBytes: Uint8Array
): string | undefined {
  if (!entry) {
    return `invalid: referenced chain entry ${event.kid} not found`
  }
  if (entry.kind !== 297) {
    return 'invalid: referenced chain entry is not Kind 297'
  }
  // Bind uid: the event's uid must match the chain entry owner
  const entryUid = entry.uid ?? entry.pubkey
  if (entryUid !== uid) {
    return 'invalid: event uid does not match chain entry uid'
  }
  // Reject revoked entries
  // Note (Phase 02 stand-in): raw DB rows do not contain a revokedBy column.
  // Full multi-entry revocation enforcement is handled by the in-memory chain cache in Phase 03.
  if (entry.revokedBy) {
    return `invalid: referenced chain entry ${event.kid} has been revoked`
  }
  const entryContent = typeof entry.content === 'string' ? JSON.parse(entry.content) : entry.content

  // Scope check for delegate entries
  // Note (Phase 02 stand-in): procedural delegation-scope check; will be replaced by EDM cache validation in Phase 03.
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
  const colonIdx = signKeyStr.indexOf(':')
  if (colonIdx === -1) {
    return 'invalid: malformed sign key in referenced chain entry'
  }
  const alg = signKeyStr.substring(0, colonIdx)
  if (alg !== 'secp256k1-schnorr') {
    return `invalid: unknown signing algorithm: ${alg}`
  }
  const pkBytes = new Uint8Array(Buffer.from(signKeyStr.substring(colonIdx + 1), 'base64'))
  if (!schnorr.verify(sigBytes, idBytes, pkBytes)) {
    return 'invalid: signature is wrong'
  }
  return undefined
}
