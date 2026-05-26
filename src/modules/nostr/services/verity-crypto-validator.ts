// eslint-disable-next-line @typescript-eslint/no-require-imports
const { schnorr } = require('@noble/curves/secp256k1.js');
import { createHash } from 'crypto';
import type { Event } from '@nostr-relay/common';

/**
 * Synchronous Verity event verification using @noble/hashes.
 *
 * This function duplicates the logic of event-validation-module's
 * verifyVerityEvent, but uses synchronous @noble/hashes instead of
 * the async Web Crypto API. This is required because @nostr-relay/core's
 * EventUtils.validate interface demands synchronous returns.
 *
 * Returns a string on error, undefined on success — matching the
 * EventUtils.validate contract.
 */
export function verifyVerityEventSync(event: Event, serializationPrefix: number): string | undefined {
  // 1. Basic field format validation
  if (!event.id || !/^[0-9a-f]{64}$/.test(event.id)) {
    return 'invalid: id is wrong';
  }
  if (!event.pubkey || !/^[0-9a-f]{64}$/.test(event.pubkey)) {
    return 'invalid: pubkey is wrong';
  }
  if (!event.sig || !/^[0-9a-f]{128}$/.test(event.sig)) {
    return 'invalid: signature is wrong';
  }

  // 2. ID verification with custom serialization prefix
  try {
    const serialized = JSON.stringify([
      serializationPrefix,
      event.pubkey,
      event.created_at,
      event.kind,
      event.tags,
      event.content,
    ]);
    const hash = createHash('sha256').update(serialized).digest();
    const computedId = hash.toString('hex');

    if (event.id !== computedId) {
      return `invalid: id is wrong. Expected ${computedId}, got ${event.id}`;
    }
  } catch (e) {
    return `invalid: id calculation failed: ${(e as Error).message}`;
  }

  // 3. Schnorr signature verification
  try {
    const sigBytes = new Uint8Array(Buffer.from(event.sig, 'hex'));
    const idBytes = new Uint8Array(Buffer.from(event.id, 'hex'));
    const pubkeyBytes = new Uint8Array(Buffer.from(event.pubkey, 'hex'));

    if (!schnorr.verify(sigBytes, idBytes, pubkeyBytes)) {
      return 'invalid: signature is wrong';
    }
  } catch (error) {
    return 'invalid: signature verification failed';
  }

  return undefined; // Valid
}
