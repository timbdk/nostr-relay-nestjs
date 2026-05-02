import { Optional } from '@nestjs/common';
import { InjectPinoLogger, PinoLogger } from 'nestjs-pino';
import { Event, Filter, IncomingMessage } from '@nostr-relay/common';
import { Validator } from '@nostr-relay/validator';
import {
  verifyVerityEvent,
  verityBaseEventSchema,
  KIND_USERNAME_REGISTRATION,
  validateUsernameRegistration,
  KIND_USER_CONFIGURATION,
  validateUserConfiguration,
  KIND_ADMIN_COMMAND,
  validateAdminCommand,
  KIND_TEXT_NOTE,
  validateTextNote
} from 'verity-event-validation-module';
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
   *
   * Uses verifyVerityEvent from event-validation-module (single source of truth
   * for custom serialization prefix verification).
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

    // Verify ID + signature using the shared module (custom serialization prefix)
    if (!verifyVerityEvent(event, this.serializationPrefix)) {
      const debugInfo = `Prefix: ${this.serializationPrefix}`;
      this.logger?.warn({ eventId: id }, `ID/signature validation failed. ${debugInfo}`);
      throw new Error('invalid: id or signature mismatch');
    }

    // Structural base validation
    const baseResult = verityBaseEventSchema.safeParse(event);
    if (!baseResult.success) {
      throw new Error(`invalid: structural validation failed - ${baseResult.error.issues[0]?.message}`);
    }

    // Kind-specific structural validation
    if (kind === KIND_USERNAME_REGISTRATION) {
      const result = validateUsernameRegistration(event);
      if (!result.success) throw new Error(`invalid: structural validation failed - ${result.error.issues[0]?.message}`);
    } else if (kind === KIND_USER_CONFIGURATION) {
      const result = validateUserConfiguration(event);
      if (!result.success) throw new Error(`invalid: structural validation failed - ${result.error.issues[0]?.message}`);
    } else if (kind === KIND_ADMIN_COMMAND) {
      const result = validateAdminCommand(event);
      if (!result.success) throw new Error(`invalid: structural validation failed - ${result.error.issues[0]?.message}`);
    } else if (kind === KIND_TEXT_NOTE) {
      const result = validateTextNote(event);
      if (!result.success) throw new Error(`invalid: structural validation failed - ${result.error.issues[0]?.message}`);
    }

    return event;
  }
}
