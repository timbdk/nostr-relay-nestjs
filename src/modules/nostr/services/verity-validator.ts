import { Optional } from '@nestjs/common'
import { InjectPinoLogger, PinoLogger } from 'nestjs-pino'
import { Event, Filter, IncomingMessage } from '@nostr-relay/common'
import { Validator } from '@nostr-relay/validator'
import {
  KindRegistry,
  registeredKinds,
  identityIdFromPublicKey
} from 'verity-event-data-module'

export class VerityValidator extends Validator {
  private readonly logger: PinoLogger | undefined
  readonly registry: KindRegistry

  constructor(
    private readonly serializationPrefix: number,
    @Optional() @InjectPinoLogger(VerityValidator.name)
    logger?: PinoLogger,
  ) {
    super()
    this.logger = logger
    this.registry = KindRegistry.fromBarrelSync(registeredKinds)
  }

  public override async validateIncomingMessage(message: any): Promise<IncomingMessage> {
    // The NestJS WebSocket gateway automatically parses JSON.
    // 'message' is already an Array here.
    const msgArray = message

    if (!Array.isArray(msgArray) || msgArray.length === 0) {
      return super.validateIncomingMessage(message)
    }

    const type = msgArray[0]
    if (type === 'EVENT') {
      if (msgArray.length < 2) throw new Error('Invalid EVENT message')
      const event = msgArray[1]
      if (event && typeof event === 'object' && !event.pubkey && event.uid) {
        event.pubkey = event.uid
      }
      return ['EVENT', event] as IncomingMessage
    }
    if (type === 'AUTH') {
      if (msgArray.length < 2) throw new Error('Invalid AUTH message')
      const event = msgArray[1]
      if (event && typeof event === 'object' && !event.pubkey && event.uid) {
        event.pubkey = event.uid
      }
      return ['AUTH', event] as IncomingMessage
    }
    if (type === 'REQ') {
      if (msgArray.length < 2) throw new Error('Invalid REQ message')
      for (let i = 2; i < msgArray.length; i++) {
        const filter = msgArray[i]
        if (filter && typeof filter === 'object') {
          // Protocol deviation: Full ML-DSA public keys and prefixed representations are rewritten
          // to 32-byte UIDs (SHA-256 digests) to match storage indexing. NIP-01 partial prefix filters
          // on ML-DSA public keys cannot be translated because SHA-256 preimage digests cannot be derived
          // from partial key prefixes.
          if (Array.isArray(filter.authors)) {
            filter.authors = filter.authors.map((a: any) =>
              typeof a === 'string' && (a.length === 2624 || a.startsWith('ml-dsa-44:')) ? identityIdFromPublicKey(a) : a
            )
          }
          if (Array.isArray(filter['#p'])) {
            filter['#p'] = filter['#p'].map((p: any) =>
              typeof p === 'string' && (p.length === 2624 || p.startsWith('ml-dsa-44:')) ? identityIdFromPublicKey(p) : p
            )
          }
        }
      }
      return super.validateIncomingMessage(msgArray)
    }

    return super.validateIncomingMessage(message)
  }

  public async validateFilter(filter: any): Promise<Filter> {
    return filter as Filter
  }

  public async validateFilters(filters: any): Promise<Filter[]> {
    return filters as Filter[]
  }

  /**
   * Validates the event and returns it, satisfying the base Validator interface.
   *
   * Use {@link validateAndResolve} when you also need the resolved variant name
   * for framework-driven authorization.
   */
  public override async validateEvent(event: any): Promise<Event> {
    const result = await this.validateAndResolve(event)
    return result.event
  }

  /**
   * SERIALIZATION:
   * [prefix, pubkey, created_at, kind, tags, content]
   *
   * Uses verifyVerityEvent from event-data-module (single source of truth
   * for custom serialization prefix verification).
   *
   * Returns the validated event and, when available, the resolved variant name
   * so that the relay's write gate can consult variant-specific publisher rules.
   */
  public async validateAndResolve(event: any): Promise<{ event: Event; variant?: string }> {
    this.logger?.debug({ eventId: event.id }, 'Validating event')

    if (typeof event !== 'object' || event === null) {
      throw new Error('Event must be an object')
    }

    if (!event.pubkey && event.uid) {
      event.pubkey = event.uid
    }

    const result = this.registry.checkStructural(event)
    if (!result.ok) {
      const err = result.errors[0]
      throw new Error(`invalid: [${err.code}]: ${err.message}`)
    }

    const resEvent = result.event as any
    if (resEvent && !resEvent.pubkey && resEvent.uid) {
      resEvent.pubkey = resEvent.uid
    }

    return { event: resEvent as Event, variant: result.variant }
  }
}
