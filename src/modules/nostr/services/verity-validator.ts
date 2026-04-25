import { Optional } from '@nestjs/common';
import { InjectPinoLogger, PinoLogger } from 'nestjs-pino';
import { Event, Filter, IncomingMessage } from '@nostr-relay/common';
import { Validator } from '@nostr-relay/validator';
import { schnorr } from '@noble/curves/secp256k1';
import { sha256 } from '@noble/hashes/sha256';
import { bytesToHex } from '@noble/hashes/utils';

export class VerityValidator extends Validator {
  private readonly logger: PinoLogger | undefined;

  constructor(
    private readonly serializationPrefix: number,
    @Optional() @InjectPinoLogger(VerityValidator.name)
    logger?: PinoLogger,
  ) {
    super();
    this.logger = logger;
  }

  public override async validateIncomingMessage(message: any): Promise<IncomingMessage> {
    // The NestJS WebSocket gateway automatically parses JSON.
    // 'message' is already an Array here.
    const msgArray = message;
    
    if (!Array.isArray(msgArray) || msgArray.length === 0) {
      return super.validateIncomingMessage(message);
    }

    const type = msgArray[0];
    if (type === 'EVENT') {
      if (msgArray.length < 2) throw new Error('Invalid EVENT message');
      return ['EVENT', msgArray[1]] as IncomingMessage;
    }
    if (type === 'AUTH') {
      if (msgArray.length < 2) throw new Error('Invalid AUTH message');
      return ['AUTH', msgArray[1]] as IncomingMessage;
    }

    return super.validateIncomingMessage(message);
  }

  public async validateFilter(filter: any): Promise<Filter> {
    return filter as Filter;
  }

  public async validateFilters(filters: any): Promise<Filter[]> {
    return filters as Filter[];
  }

  /**
   * SERIALIZATION:
   * [prefix, pubkey, created_at, kind, tags, content]
   */
  public async validateEvent(event: any): Promise<Event> {
    this.logger?.debug({ eventId: event.id }, 'Validating event');

    if (typeof event !== 'object' || event === null) {
      throw new Error('Event must be an object');
    }

    const { id, pubkey, created_at, kind, tags, content, sig } = event;

    if (typeof id !== 'string' || !/^[0-9a-f]{64}$/.test(id)) {
      throw new Error('invalid id');
    }
    if (typeof pubkey !== 'string' || !/^[0-9a-f]{64}$/.test(pubkey)) {
      throw new Error('invalid pubkey');
    }
    if (typeof created_at !== 'number') {
      throw new Error('invalid created_at');
    }
    if (typeof kind !== 'number') {
      throw new Error('invalid kind');
    }
    if (!Array.isArray(tags)) {
      throw new Error('invalid tags');
    }
    if (typeof content !== 'string') {
      throw new Error('invalid content');
    }
    if (typeof sig !== 'string' || !/^[0-9a-f]{128}$/.test(sig)) {
      throw new Error('invalid sig');
    }

    // 2. Calculate ID using Custom Serialization
    const serialized = JSON.stringify([
      this.serializationPrefix,
      pubkey,
      created_at,
      kind,
      tags,
      content,
    ]);
    const hash = sha256(new TextEncoder().encode(serialized));
    const computedId = bytesToHex(hash);

    if (id !== computedId) {
      const debugInfo = `Expected ${computedId}, got ${id}. Prefix: ${this.serializationPrefix}`;
      this.logger?.warn({ eventId: id, computedId, expectedId: computedId }, 'ID validation failed');
      throw new Error(`invalid: id is wrong. ${debugInfo}`);
    }

    // 3. Verify Signature
    try {
      const isValid = await schnorr.verify(sig, id, pubkey);
      if (!isValid) {
        throw new Error('invalid signature');
      }
    } catch (e) {
      throw new Error('invalid signature');
    }

    return event;
  }
}
