import { Injectable, OnApplicationShutdown, Optional } from '@nestjs/common'
import { ConfigService } from '@nestjs/config'
import {
  Event,
  Filter,
  createOutgoingNoticeMessage,
  EventUtils,
} from '@nostr-relay/common'
import { createHash, randomUUID } from 'crypto'
import {
  type ValidationContext,
  evaluateReadPolicy,
  type ReadPolicyContext,
} from 'verity-event-data-module'
import { NostrRelay } from '@nostr-relay/core'
import { CreatedAtLimitGuard } from '@nostr-relay/created-at-limit-guard'
import { OrGuard } from '@nostr-relay/or-guard'
import { PowGuard } from '@nostr-relay/pow-guard'
import { Throttler } from '@nostr-relay/throttler'
import { VerityValidator } from './verity-validator'
import { verifyVerityEventSync } from './verity-crypto-validator'
import { InjectPinoLogger, PinoLogger } from 'nestjs-pino'
import { Config } from 'src/config'
import { MessageHandlingConfig } from 'src/config/message-handling.config'
import { WebSocket } from 'ws'
import { ValidationError } from 'zod-validation-error'
import { WotService } from '../../../modules/wot/wot.service'
import { MetricService } from '../../metric/metric.service'
import { EventRepository } from '../../repositories/event.repository'
import { NostrRelayLogger } from '../../share/nostr-relay-logger.service'
import { TestingCheckpointService } from '../../testing/testing-checkpoint.service'
import { BlacklistGuardPlugin, WhitelistGuardPlugin } from '../plugins'

@Injectable()
export class NostrRelayService implements OnApplicationShutdown {
  private readonly relay: NostrRelay
  private readonly messageHandlingConfig: MessageHandlingConfig
  private readonly validator: VerityValidator
  private readonly throttler: Throttler
  private readonly trustedSignerPubkey: string[] | undefined
  private readonly trustedSignerUids: string[] | undefined

  constructor(
    @InjectPinoLogger(NostrRelayService.name)
    private readonly logger: PinoLogger,
    private readonly metricService: MetricService,
    nostrRelayLogger: NostrRelayLogger,
    private readonly eventRepository: EventRepository,
    private readonly configService: ConfigService<Config, true>,
    wotService: WotService,
    @Optional() private readonly checkpointService?: TestingCheckpointService,
  ) {
    const hostname = configService.get('hostname')
    const relayUrl = configService.get('relayUrl')
    const trustedSignerPubkey = configService.get('trustedSignerPubkey')
    const rawList: string[] = Array.isArray(trustedSignerPubkey)
      ? trustedSignerPubkey
      : typeof trustedSignerPubkey === 'string'
        ? trustedSignerPubkey.split(',').map((s: string) => s.trim()).filter(Boolean)
        : []
    this.trustedSignerPubkey = rawList
    this.trustedSignerUids = rawList.map((pk: string) =>
      createHash('sha256').update(new Uint8Array(Buffer.from(pk, 'hex'))).digest('hex'),
    )
    const serializationPrefix = configService.get('serializationPrefix')
    const {
      createdAtLowerLimit,
      createdAtUpperLimit,
      minPowDifficulty,
      maxSubscriptionsPerClient,
      blacklist,
      whitelist,
    } = configService.get('limit', { infer: true })
    const cacheConfig = configService.get('cache', { infer: true })
    const throttlerConfig = configService.get('throttler.ws', { infer: true })
    this.messageHandlingConfig = configService.get('messageHandling', {
      infer: true,
    })
    let relayHostname = hostname
    if (relayUrl) {
      try {
        const url = new URL(relayUrl)
        relayHostname = url.hostname // Must be hostname only (no port) for EventUtils validation
        this.logger.info(`[DEBUG] Configured NostrRelay with RELAY_URL=${relayUrl} -> hostname=${relayHostname}`)
      } catch (error) {
        this.logger.warn(`Invalid RELAY_URL: ${relayUrl}`)
      }
    }

    this.relay = new NostrRelay(eventRepository, {
      hostname: relayHostname,
      logger: nostrRelayLogger,
      maxSubscriptionsPerClient,
      ...cacheConfig,
      // WORKAROUND: @nostr-relay/core has a race condition in LazyCache that randomly returns undefined
      // and crashes handleEventMessage. We disable the event handling cache to bypass it.
      eventHandlingResultCacheTtl: 0,
    })
    this.validator = new VerityValidator(serializationPrefix)

    /**
     * SAFE PLUGIN WRAPPING
     *
     * STRUCTURAL DESIGN NOTE:
     * This wrapper is a defensive measure against a structural flaw in the @nostr-relay ecosystem
     * where return type conventions (success vs canHandle) are inconsistent and guards frequently
     * return undefined on success, causing crashes in @nostr-relay/core.
     */
    const wrapInSafety = (plugin: any): any => {
      if (!plugin || typeof plugin.beforeHandleEvent !== 'function') {
        return plugin
      }
      const target = plugin
      const originalBefore = target.beforeHandleEvent.bind(target)
      target.beforeHandleEvent = async (event: any, client?: any): Promise<any> => {
        const result = await originalBefore(event, client)
        if (result === undefined || result === null) {
          return { canHandle: true, success: true }
        }
        if (typeof result === 'object') {
          if (result.success && !('canHandle' in result)) result.canHandle = true
          if (result.canHandle && !('success' in result)) result.success = true
        }
        return result
      }
      return plugin
    }

    this.throttler = new Throttler(throttlerConfig)
    this.relay.register(wrapInSafety(this.throttler))

    const createdAtLimitGuardPlugin = new CreatedAtLimitGuard({
      lowerLimit: createdAtLowerLimit,
      upperLimit: createdAtUpperLimit,
    })
    const wotGuard = wotService.getWotGuardPlugin()
    const orGuardPlugin = new OrGuard()
    let hasOrGuards = false

    if (wotGuard && wotGuard.getEnabled()) {
      orGuardPlugin.addGuard(wrapInSafety(wotGuard))
      hasOrGuards = true
    }

    if (minPowDifficulty > 0) {
      const powGuardPlugin = new PowGuard(minPowDifficulty)
      orGuardPlugin.addGuard(wrapInSafety(powGuardPlugin))
      hasOrGuards = true
    }

    if (blacklist?.length) {
      const blacklistGuardPlugin = new BlacklistGuardPlugin(blacklist)
      this.relay.register(wrapInSafety(blacklistGuardPlugin))
    }

    if (whitelist?.length) {
      const whitelistGuardPlugin = new WhitelistGuardPlugin(whitelist)
      orGuardPlugin.addGuard(wrapInSafety(whitelistGuardPlugin))
      hasOrGuards = true
    }

    if (hasOrGuards) {
      this.relay.register(wrapInSafety(orGuardPlugin))
    }

    // Monkey-patch EventUtils.validate to use our extracted crypto function.
    (EventUtils as any).validate = (event: Event) => {
      return verifyVerityEventSync(event, serializationPrefix)
    }

    this.relay.register(wrapInSafety(createdAtLimitGuardPlugin))
  }

  onApplicationShutdown() {
    this.throttler.destroy()
  }

  private readonly authenticatedSigners = new WeakMap<WebSocket, string>()
  private readonly resolvedIdentities = new WeakMap<WebSocket, string>()
  /** Persistent device→user identity mapping (survives connection lifecycles). */
  private readonly deviceIdentities = new Map<string, string>()
  private readonly authChallenges = new WeakMap<WebSocket, string>()

  /**
   * Check if a uid corresponds to a trusted signer (signer-service, auth-hooks, or test registrar).
   * Compares connection uid against H(TRUSTED_SIGNER_PUBKEY).
   * Returns false for undefined/null uids.
   */
  private isTrustedSigner(uid: string | undefined): boolean {
    if (!uid) return false
    const trustedUids = this.trustedSignerUids
    if (!trustedUids) return false
    return trustedUids.includes(uid)
  }

  /**
   * Builds a ReadPolicyContext for a given client connection.
   * - devicePubkey: NIP-42 authenticated device uid (grants 'public' tier)
   * - userPubkey: resolved user identity via Kind 24135 attestation (grants 'authenticated' tier)
   */
  private buildReadContext(client: WebSocket): ReadPolicyContext {
    const devicePubkey = this.authenticatedSigners.get(client)

    // Resolved identity lookup:
    // 1. Try the per-connection WeakMap (set when attestation arrived on an active connection)
    // 2. Fall back to the persistent Map (set from attestations that arrived between connections)
    let userPubkey = this.resolvedIdentities.get(client)
    if (!userPubkey && devicePubkey) {
      userPubkey = this.deviceIdentities.get(devicePubkey)
    }

    return { devicePubkey, userPubkey }
  }

  /**
   * Resolves the user identity for a device key connection.
   * Called when a Kind 24135 event with 'client' and 'user' attestation tags is observed.
   * Maps: device uid → user uid (for read policy 'authenticated' tier access).
   */
  private resolveIdentity(clientPubkey: string, userPubkey: string): void {
    const clientUid = /^[a-f0-9]{64}$/i.test(clientPubkey)
      ? createHash('sha256').update(new Uint8Array(Buffer.from(clientPubkey, 'hex'))).digest('hex')
      : clientPubkey
    const userUid = /^[a-f0-9]{64}$/i.test(userPubkey)
      ? createHash('sha256').update(new Uint8Array(Buffer.from(userPubkey, 'hex'))).digest('hex')
      : userPubkey

    // Always persist the mapping so future connections can use it.
    // Canonical mapping: device identifier (pubkey or uid) → user uid (for read policy checks).
    this.deviceIdentities.set(clientPubkey, userUid)
    this.deviceIdentities.set(clientUid, userUid)

    // Apply to all currently-active connections for this device key.
    const connections = this.authenticatedConnections.get(clientUid) || this.authenticatedConnections.get(clientPubkey)
    if (connections) {
      for (const ws of connections) {
        this.resolvedIdentities.set(ws, userUid)
      }
      this.logger.info(
        `[IDENTITY] Resolved identity: device=${clientPubkey.substring(0, 8)} (${clientUid.substring(0, 8)}) → user=${userPubkey.substring(0, 8)} (${userUid.substring(0, 8)}) (${connections.size} connection(s))`,
      )
      this.checkpointService?.broadcast('relay.identity.resolved', {
        devicePubkey: clientPubkey.substring(0, 16),
        userPubkey: userPubkey.substring(0, 16),
        connections: connections.size,
      })
    } else {
      this.logger.info(
        `[IDENTITY] Stored identity (no active connections): device=${clientPubkey.substring(0, 8)} (${clientUid.substring(0, 8)}) → user=${userPubkey.substring(0, 8)} (${userUid.substring(0, 8)})`,
      )
    }
  }

  // Forward lookup: authenticated uid → Set<WebSocket> (for identity resolution)
  // A device may have multiple concurrent WebSocket connections.
  private readonly authenticatedConnections = new Map<string, Set<WebSocket>>()

  handleConnection(client: WebSocket, ip = 'unknown') {
    // Intercept the core's AUTH challenge to capture it for our verification layer.
    // The @nostr-relay/core sends ["AUTH", ctx.id] (a UUID) when hostname is configured.
    // We must NOT send a second challenge — the NDK client uses the first one it receives.
    //
    // Read Policy: This same interception point filters outbound EVENT messages
    // through the read policy evaluator, ensuring subscribers only receive events
    // they're authorized to see.
    const originalSend = client.send.bind(client)
    client.send = (data: string | Buffer, ...args: any[]) => {
      try {
        const raw = typeof data === 'string' ? data : data.toString()
        const parsed = JSON.parse(raw)
        if (Array.isArray(parsed)) {
          // AUTH challenge capture (existing behavior)
          if (parsed[0] === 'AUTH' && typeof parsed[1] === 'string') {
            this.authChallenges.set(client, parsed[1])
            this.checkpointService?.broadcast('relay.auth.challenge_sent', {
              challenge: parsed[1].substring(0, 16),
            })
          }

          // Read Policy: filter outbound EVENT messages
          // Format: ["EVENT", subscriptionId, event]
          if (parsed[0] === 'EVENT' && parsed[2] && typeof parsed[2] === 'object') {
            // Trusted signers bypass read policy — they are system services
            // (e.g. the signer daemon) that use a single NIP-42 connection
            // but subscribe to events for multiple user keys.
            const senderPubkey = this.authenticatedSigners.get(client)
            const isTrusted = senderPubkey && this.isTrustedSigner(senderPubkey)
            if (!isTrusted) {
              const context = this.buildReadContext(client)
              if (!evaluateReadPolicy(parsed[2], context)) {
                // Silently drop — the subscriber is not authorized to see this event
                return
              }
            }
          }
        }
      } catch {
        /* not JSON, ignore */
      }
      return originalSend(data, ...args)
    }

    this.relay.handleConnection(client, ip)
    this.metricService.incrementConnectionCount()
  }

  handleDisconnect(client: WebSocket) {
    // Clean up forward lookup on disconnect
    const pubkey = this.authenticatedSigners.get(client)
    if (pubkey) {
      const connections = this.authenticatedConnections.get(pubkey)
      if (connections) {
        connections.delete(client)
        if (connections.size === 0) {
          this.authenticatedConnections.delete(pubkey)
        }
      }
    }
    this.relay.handleDisconnect(client)
    this.metricService.decrementConnectionCount()
  }

  async handleMessage(client: WebSocket, data: Array<any>): Promise<void> {
    let msg: any
    try {
      const start = Date.now()
      msg = await this.validator.validateIncomingMessage(data)
      if (!this.messageHandlingConfig[msg[0].toLowerCase()]) {
        return
      }

      // Checkpoint Broadcasting & Debug Logging (testing/development only)
      if (
        process.env.NODE_ENV === 'testing' ||
        process.env.NODE_ENV === 'development'
      ) {
        const msgType = msg[0]
        if (msgType === 'EVENT' && msg[1]) {
          const event = msg[1]
          const kind = event.kind
          const tags = Array.isArray(event.tags) ? event.tags : []
          const pTags = tags
            .filter((t: string[]) => t[0] === 'p')
            .map((t: string[]) => t[1])
          const eventUid = event.uid ?? event.pubkey

          // Broadcast checkpoint for ALL event kinds so the test runner can
          // trace any publish (e.g., kind 30598 config events from the browser).
          this.checkpointService?.broadcast('relay.event.received', {
            kind,
            pubkey: eventUid?.substring(0, 16),
            id: event.id?.substring(0, 16),
            pTags: pTags.map((p: string) => p?.substring(0, 16)),
          })

          // NIP-46 detailed logging (kinds 24133/24134/24135)
          if (kind === 24133 || kind === 24134 || kind === 24135) {
            this.logger.info(
              `[NIP46-EVENT] Received kind=${kind} id=${event.id?.substring(
                0,
                8,
              )} from=${eventUid?.substring(0, 8)} to=[${pTags
                .map((p: string) => p?.substring(0, 8))
                .join(',')}]`,
            )
          }

          // Identity Resolution: Kind 24135 events with 'client' and 'user' tags
          // provide identity attestation from the signer. Use them to resolve
          // device key → user uid for read policy 'authenticated' tier access.
          if (kind === 24135) {
            const clientTag = tags.find((t: string[]) => t[0] === 'client')?.[1]
            const userTag = tags.find((t: string[]) => t[0] === 'user')?.[1]
            if (clientTag && userTag) {
              this.resolveIdentity(clientTag, userTag)
            }
          }
        } else if (msgType === 'REQ' && msg.length > 2) {
          // Log subscriptions that might be for NIP-46
          const subscriptionId = msg[1]
          const filters = msg.slice(2)
          const hasNip46Kinds = filters.some(
            (f: any) =>
              f.kinds && (f.kinds.includes(24133) || f.kinds.includes(24134) || f.kinds.includes(24135)),
          )
          if (hasNip46Kinds) {
            const pFilters = filters.map((f: any) => f['#p'] || [])
            this.logger.info(
              `[NIP46-SUB] REQ id=${subscriptionId} #p=${JSON.stringify(
                pFilters.flat().map((p: string) => p?.substring(0, 8)),
              )}`,
            )
          }
        }
      }

      // Enforce Trusted Signer if configured
      // NIP-42 AUTH handling
      if (msg[0] === 'AUTH') {
        const authEvent = msg[1]
        const authUid = authEvent.uid ?? authEvent.pubkey

        this.checkpointService?.broadcast('relay.auth.received', {
          pubkey: authUid?.substring(0, 16),
          isTrusted: this.isTrustedSigner(authUid),
        })

        // 1. Verify challenge
        const expectedChallenge = this.authChallenges.get(client)
        const challengeInEvent = authEvent.tags?.find((t: string[]) => t[0] === 'challenge')?.[1]

        if (!expectedChallenge || challengeInEvent !== expectedChallenge) {
          this.logger.warn(`[AUTH] Challenge mismatch for ${authUid}`)
          this.checkpointService?.broadcast('relay.auth.rejected', {
            pubkey: authUid?.substring(0, 16),
            reason: 'challenge_mismatch',
          })
          client.send(JSON.stringify(['OK', authEvent.id, false, 'auth: challenge mismatch']))
          return
        }

        // 2. Complete cryptographic validation (self-certifying verify: uid == H(key), schnorr vs carried key)
        const validationError = EventUtils.validate(authEvent)
        if (validationError) {
          this.logger.warn(`[AUTH] Event validation failed for ${authUid}: ${validationError}`)
          this.checkpointService?.broadcast('relay.auth.rejected', {
            pubkey: authUid?.substring(0, 16),
            reason: 'validation_failed',
            detail: validationError,
          })
          client.send(JSON.stringify(['OK', authEvent.id, false, validationError]))
          return
        }

        // 3. Success (ANY UID ALLOWED to authenticate their connection)
        this.authenticatedSigners.set(client, authUid)
        // Maintain forward lookup for identity resolution
        const existingConnections = this.authenticatedConnections.get(authUid)
        if (existingConnections) {
          existingConnections.add(client)
        } else {
          this.authenticatedConnections.set(authUid, new Set([client]))
        }

        // Apply any previously-stored identity for this device key.
        const storedIdentity = this.deviceIdentities.get(authUid)
        if (storedIdentity) {
          this.resolvedIdentities.set(client, storedIdentity)
        }

        this.checkpointService?.broadcast('relay.auth.success', {
          pubkey: authUid?.substring(0, 16),
          isTrusted: this.isTrustedSigner(authUid),
        })

        if (this.isTrustedSigner(authUid)) {
          this.logger.info(`[AUTH] Successfully authenticated as trusted signer: ${authUid.substring(0, 16)}`)
        } else {
          this.logger.info(`[AUTH] Successfully authenticated as client: ${authUid.substring(0, 16)}`)
        }
        client.send(JSON.stringify(['OK', authEvent.id, true, 'auth: success']))
        return
      }

      // EVENT Write Authorization Pipeline
      // Security ordering: NIP-42 → crypto → connection policies → registry.check → core
      if (msg[0] === 'EVENT' && msg[1]) {
        const event = msg[1]
        const eventUid = event.uid ?? event.pubkey

        const authenticatedPubkey = this.authenticatedSigners.get(client)
        const isTrustedConnection = this.isTrustedSigner(authenticatedPubkey)

        const buildRejectionMessage = (reason: string) => {
          return JSON.stringify(['OK', event.id, false, reason])
        }

        // Step 1: NIP-42 gate (cheapest check — no DB, no crypto)
        if (!authenticatedPubkey) {
          this.logger.warn(
            `[EVENT] Rejected event from unauthenticated connection. Event uid: ${eventUid?.substring(0, 16)}`,
          )

          // Crucial for NDK: Send the AUTH challenge alongside the auth-required rejection
          // so that the client's connectivity layer immediately triggers its authentication flow.
          const challenge = this.authChallenges.get(client) || randomUUID()
          this.authChallenges.set(client, challenge)
          client.send(JSON.stringify(['AUTH', challenge]))

          return client.send(buildRejectionMessage(
            'auth-required: backend authentication required',
          ))
        }

        // Step 2: Crypto verification (before any content inspection)
        const cryptoError = verifyVerityEventSync(event, this.configService.get('serializationPrefix'))
        if (cryptoError) {
          return client.send(buildRejectionMessage(cryptoError))
        }

        // Step 3: Connection-level policies (Kind 415, NIP-46)
        if (event.kind === 415 && !isTrustedConnection) {
          return client.send(buildRejectionMessage(
            'restricted: Kind 415 requires trusted connection',
          ))
        }

        // Step 4: Framework-driven validation (structural + publisher + context)
        const self = this
        const validationContext: ValidationContext = {
          async checkUserIsRegistered(uid) {
            // Retry loop to handle race conditions with DB writes
            const maxAttempts = 3
            for (let attempt = 0; attempt < maxAttempts; attempt++) {
              const events = await self.findEvents(
                [{ kinds: [415], authors: [uid], limit: 1 }],
              )
              if (events.length > 0) return true
              if (attempt < maxAttempts - 1) {
                await new Promise((resolve) => setTimeout(resolve, 100))
              }
            }
            return false
          },
          async checkParentEventExists(eventId) {
            const events = await self.findEvents(
              [{ ids: [eventId], limit: 1 }],
            )
            return events.length > 0
          },
        }

        const checkResult = await this.validator.registry.check(event, {
          context: validationContext,
          trustedSigners: this.trustedSignerUids,
          skipPublisherCheck: isTrustedConnection,
          skipContextCheck: false,
        })

        if (!checkResult.ok) {
          const firstError = checkResult.errors[0]
          const reason = `invalid: [${firstError.code}]: ${firstError.message}`
          return client.send(buildRejectionMessage(reason))
        }
      }

      await this.relay.handleMessage(client, msg as any)
      this.metricService.pushProcessingTime(msg[0] as any, Date.now() - start)

      // Post-processing checkpoint for ALL events so the test runner can verify
      // that any publish (e.g., kind 30598 config events) was actually stored.
      if (this.checkpointService && (msg as any)[0] === 'EVENT' && (msg as any)[1]) {
        const event = (msg as any)[1]
        const eventUid = event.uid ?? event.pubkey
        this.checkpointService.broadcast('relay.event.processed', {
          kind: event.kind,
          pubkey: eventUid?.substring(0, 16),
          id: event.id?.substring(0, 16),
        })
      }
    } catch (error) {
      if (error instanceof ValidationError) {
        client.send(JSON.stringify(createOutgoingNoticeMessage(error.message)))
        return
      }
      this.logger.error(error)
      client.send(JSON.stringify(createOutgoingNoticeMessage((error as Error).message)))
    }
  }

  async handleEvent(event: Event) {
    return await this.relay.handleEvent(event)
  }

  async findEvents(filters: Filter[], pubkey?: string) {
    return await this.relay.findEvents(filters, pubkey)
  }

  async validateEvent(data: any) {
    const result = await this.validator.validateAndResolve(data)
    return result.event
  }

  async validateFilter(data: any) {
    return await this.validator.validateFilter(data)
  }

  async validateFilters(data: any) {
    return await this.validator.validateFilters(data)
  }
}
